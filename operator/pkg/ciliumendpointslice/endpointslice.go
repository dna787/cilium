// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/workerpool"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/k8s"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	capi_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// cesNamePrefix is the prefix name added for the CiliumEndpointSlice
	// resource.
	cesNamePrefix = "ces"

	// defaultSyncBackOff is the default backoff period for cesSync calls.
	defaultSyncBackOff = 1 * time.Second
	// maxSyncBackOff is the max backoff period for cesSync calls.
	maxSyncBackOff = 100 * time.Second
	// maxRetries is the number of times a cesSync will be retried before it is
	// dropped out of the queue.
	maxRetries = 15

	// deprecatedIdentityMode is the old name of `identity` mode. It is kept for backwards
	// compatibility but will be removed in the future.
	deprecatedIdentityMode = "cesSliceModeIdentity"
	// deprecatedFcfsMode is the old name of `fcfs` mode. It is kept for backwards
	// compatibility but will be removed in the future.
	deprecatedFcfsMode = "cesSliceModeFCFS"
	// CEPs are batched into a CES, based on its Identity
	identityMode = "identity"
	// CEPs are inserted into the largest, non-empty CiliumEndpointSlice
	fcfsMode = "fcfs"

	// Default CES Synctime, multiple consecutive syncs with k8s-apiserver are
	// batched and synced together after a short delay.
	DefaultCESSyncTime = 500 * time.Millisecond

	// Force CES update
	ForceCESSyncTime = 5 * time.Millisecond

	CESWriteQPSLimitMax = 50
	CESWriteQPSBurstMax = 100
)

type cepPriority uint32

const (
	High    cepPriority = 0
	Default cepPriority = math.MaxUint32
)

func (c cepPriority) isLess(rv cepPriority) bool {
	return c > rv
}

func equalCeps2(cep0 *cilium_api_v2.CiliumEndpoint, cep1 *coreCiliumEndpointNS) bool {
	return cep0.Name == cep1.ccep.Name && cep0.Namespace == cep1.ns
}

func equalCeps(cep0, cep1 *coreCiliumEndpointNS) bool {
	return cep0.ccep.Name == cep1.ccep.Name && cep0.ns == cep1.ns
}

func getPriority(s string) cepPriority {
	if num, err := strconv.ParseUint(s, 10, 32); err == nil {
		return cepPriority(num)
	}
	return Default
}

type coreCiliumEndpointNS struct {
	ccep *cilium_v2alpha1.CoreCiliumEndpoint
	ns   string
}

type coreCiliumEndpointInfo struct {
	cep      *coreCiliumEndpointNS
	priority cepPriority
}

type priorityFilter struct {
	mutex       lock.RWMutex
	ipToCepList map[string][]coreCiliumEndpointInfo
}

var filter priorityFilter
var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "filter")

func getCepPriority(cep *cilium_api_v2.CiliumEndpoint) cepPriority {
	var priority cepPriority = Default
	for _, lbl := range cep.Status.Identity.Labels {
		if !strings.Contains(lbl, labels.IDNamePriority) {
			continue
		}

		parts := strings.SplitN(lbl, "=", 2)
		if len(parts) < 2 {
			continue
		}

		priority = getPriority(parts[1])
		break
	}

	if lbl, exist := cep.Labels[labels.IDNamePriority]; exist {
		priority = getPriority(lbl)
	}

	return priority
}

func getCepAddressPair(cep *cilium_api_v2.CiliumEndpoint) cilium_api_v2.AddressPair {
	var shared cilium_api_v2.AddressPair
	for _, pair := range cep.Status.Networking.Addressing {
		if pair.IPV4 == "" {
			continue
		}
		shared = *pair
		break
	}
	return shared
}

func (c *priorityFilter) getCoreCiliumEndpoint(cep *cilium_api_v2.CiliumEndpoint) *cilium_v2alpha1.CoreCiliumEndpoint {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	shared := getCepAddressPair(cep)
	if shared.IPV4 == "" {
		log.Warn("CEP have not address", logfields.CEPName, cep.Name)
		return nil
	}

	cepList, exist := c.ipToCepList[shared.IPV4]
	if !exist {
		log.Warn("CEP not found in filter map", logfields.CEPName, cep.Name)
		return nil
	}

	var ccep *cilium_v2alpha1.CoreCiliumEndpoint
	for i := range cepList {
		if equalCeps2(cep, cepList[i].cep) {
			ccep = cepList[i].cep.ccep
			break
		}
	}
	return ccep
}

func FilterGetCoreCiliumEndpoint(cep *cilium_api_v2.CiliumEndpoint) *cilium_v2alpha1.CoreCiliumEndpoint {
	return filter.getCoreCiliumEndpoint(cep)
}

// WARNING this update logic will work only if CEP(new and old) network addresses is not changed !!!
// If some address was removed in new CEP - it will never removed from map
// filter support only one ip4 address for pod
func (c *priorityFilter) filterAddressByPriority(cep *cilium_api_v2.CiliumEndpoint) (*coreCiliumEndpointNS, time.Duration, *coreCiliumEndpointNS) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	ccep := &coreCiliumEndpointNS{
		ccep: k8s.ConvertCEPToCoreCEP(cep),
		ns:   cep.GetNamespace(),
	}

	newOwner := ccep
	var oldOwner *coreCiliumEndpointNS
	delay := DefaultCESSyncTime

	shared := getCepAddressPair(cep)
	if shared.IPV4 == "" {
		log.Warn("CEP have not address", logfields.CEPName, cep.Name)
		return oldOwner, delay, newOwner
	}

	priority := getCepPriority(cep)
	info := coreCiliumEndpointInfo{
		cep:      ccep,
		priority: priority,
	}

	if cepList, exist := c.ipToCepList[shared.IPV4]; exist {
		isInserted := false
		// new cep will have higher priority than old ceps with same priority
		highest := &info
		currentOwner := cepList[0].cep
		for i := range cepList {
			if len(cepList[i].cep.ccep.Networking.Addressing) != 0 {
				currentOwner = cepList[i].cep
			}
			if equalCeps(ccep, cepList[i].cep) {
				isInserted = true
				cepList[i].cep = ccep
				// forced update only on first appearance
				if cepList[i].priority != priority && priority == High {
					delay = ForceCESSyncTime
				}
				cepList[i].priority = priority
			}
			if highest.priority.isLess(cepList[i].priority) {
				highest = &cepList[i]
			}
		}
		if !isInserted {
			if priority == High {
				delay = ForceCESSyncTime
			}
			c.ipToCepList[shared.IPV4] = append(cepList, info)
		}
		// possibly cases:
		// 1) income cep is highest and already ip4 owner(only update income cep)
		// 2) income cep is highest and replace other owner cep(hide ip4 address for previous owner and make owner income cep)
		// 3) income cep is lowest and need to be replaced by other cep
		// 4) income cep is lowest and other cep is already owner
		emptyAddrList := cilium_api_v2.AddressPairList{}
		isOwner := equalCeps(ccep, currentOwner)
		isHighest := equalCeps(ccep, highest.cep)
		if isOwner && isHighest {
			// just skip
			log.Debug("CEP is already address owner", logfields.CEPName, newOwner.ccep.Name)
		} else if isOwner && !isHighest {
			ccep.ccep.Networking.Addressing = emptyAddrList
			addr := &cilium_api_v2.AddressPair{
				IPV4: shared.IPV4,
				IPV6: shared.IPV6,
			}
			highest.cep.ccep.Networking.Addressing = append(emptyAddrList, addr)
			oldOwner = ccep
			newOwner = highest.cep
			log.Debug("CEP loses ownership of address", logfields.CEPName, oldOwner.ccep.Name, newOwner.ccep.Name)
		} else if !isOwner && isHighest {
			currentOwner.ccep.Networking.Addressing = emptyAddrList
			oldOwner = currentOwner
			log.Debug("CEP takes ownership of address", logfields.CEPName, newOwner.ccep.Name, oldOwner.ccep.Name)
		} else { // !isOwner && !isHighest
			ccep.ccep.Networking.Addressing = emptyAddrList
			log.Debug("CEP is not address owner", logfields.CEPName, newOwner.ccep.Name)
		}
	} else {
		c.ipToCepList[shared.IPV4] = []coreCiliumEndpointInfo{info}
		if priority == High {
			delay = ForceCESSyncTime
		}
	}
	return oldOwner, delay, newOwner
}

func (c *priorityFilter) removeCEPFromFilter(cep *cilium_api_v2.CiliumEndpoint) *coreCiliumEndpointNS {
	if cep.Status.Networking == nil || cep.GetName() == "" || cep.Namespace == "" {
		return nil
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// filter support only one ip4 address for pod
	shared := getCepAddressPair(cep)
	if shared.IPV4 == "" {
		log.Warn("CEP have not address", logfields.CEPName, cep.Name)
		return nil
	}

	ccep := &coreCiliumEndpointNS{
		ccep: k8s.ConvertCEPToCoreCEP(cep),
		ns:   cep.GetNamespace(),
	}
	var hiddenCep *coreCiliumEndpointNS
	if cepList, exist := c.ipToCepList[shared.IPV4]; exist {
		if len(cepList) == 1 {
			prev := cepList[0]
			if equalCeps(prev.cep, ccep) {
				delete(filter.ipToCepList, shared.IPV4)
			}
			return nil
		}
		needRestoring := false
		// remove CEP from slice with several elements
		newList := []coreCiliumEndpointInfo{}
		for _, prev := range cepList {
			if !equalCeps(prev.cep, ccep) {
				newList = append(newList, prev)
			} else {
				log.Debug("CEP is removed from filter", logfields.CEPName, cep.Name)
				// if removed CEP have address - restoring hidden CEP
				needRestoring = len(prev.cep.ccep.Networking.Addressing) != 0
			}
		}
		c.ipToCepList[shared.IPV4] = newList
		if !needRestoring {
			return nil
		}
		// find most priorioty hidden cep for restoring its network access
		highest := &newList[0]
		for i := 1; i < len(newList); i++ {
			if newList[i].priority.isLess(highest.priority) {
				highest = &newList[i]
			}
		}
		hiddenCep = highest.cep
		hiddenCep.ccep.Networking.Addressing = append(hiddenCep.ccep.Networking.Addressing, &shared)
		log.Debug("Hidden CEP is restored", logfields.CEPName, hiddenCep.ccep.Name)
	}
	return hiddenCep
}

func (c *Controller) initializeQueue() {
	c.logger.Info("CES controller workqueue configuration",
		logfields.WorkQueueQPSLimit, c.rateLimit.current.Limit,
		logfields.WorkQueueBurstLimit, c.rateLimit.current.Burst,
		logfields.WorkQueueSyncBackOff, defaultSyncBackOff)

	// Single rateLimiter controls the number of processed events in both queues.
	c.rateLimiter = workqueue.NewTypedItemExponentialFailureRateLimiter[CESKey](defaultSyncBackOff, maxSyncBackOff)
	c.fastQueue = workqueue.NewTypedRateLimitingQueueWithConfig(
		c.rateLimiter,
		workqueue.TypedRateLimitingQueueConfig[CESKey]{Name: "cilium_endpoint_slice"})
	c.standardQueue = workqueue.NewTypedRateLimitingQueueWithConfig(
		c.rateLimiter,
		workqueue.TypedRateLimitingQueueConfig[CESKey]{Name: "cilium_endpoint_slice"})
}

func (c *Controller) onEndpointUpdate(cep *cilium_api_v2.CiliumEndpoint) {
	if cep.Status.Networking == nil || cep.Status.Identity == nil || cep.GetName() == "" || cep.Namespace == "" {
		return
	}

	oldOwner, delay, newOwner := filter.filterAddressByPriority(cep)
	if oldOwner != nil {
		touchedCESs := c.manager.UpdateCEPMapping(oldOwner.ccep, oldOwner.ns)
		c.enqueueCESReconciliation(touchedCESs, delay)
	}

	touchedCESs := c.manager.UpdateCEPMapping(newOwner.ccep, newOwner.ns)
	c.enqueueCESReconciliation(touchedCESs, delay)
}

func (c *Controller) onEndpointDelete(cep *cilium_api_v2.CiliumEndpoint) {
	hiddenCep := filter.removeCEPFromFilter(cep)

	if hiddenCep != nil {
		touchedCESs := c.manager.UpdateCEPMapping(hiddenCep.ccep, hiddenCep.ns)
		c.enqueueCESReconciliation(touchedCESs, DefaultCESSyncTime)
	}

	touchedCES := c.manager.RemoveCEPMapping(k8s.ConvertCEPToCoreCEP(cep), cep.Namespace)
	c.enqueueCESReconciliation([]CESKey{touchedCES}, DefaultCESSyncTime)
}

func (c *Controller) onSliceUpdate(ces *capi_v2a1.CiliumEndpointSlice) {
	c.enqueueCESReconciliation([]CESKey{NewCESKey(ces.Name, ces.Namespace)}, DefaultCESSyncTime)
}

func (c *Controller) onSliceDelete(ces *capi_v2a1.CiliumEndpointSlice) {
	c.enqueueCESReconciliation([]CESKey{NewCESKey(ces.Name, ces.Namespace)}, DefaultCESSyncTime)
}

func (c *Controller) addToQueue(ces CESKey, delay time.Duration) {
	c.priorityNamespacesLock.RLock()
	_, exists := c.priorityNamespaces[ces.Namespace]
	c.priorityNamespacesLock.RUnlock()
	time.AfterFunc(delay, func() {
		c.cond.L.Lock()
		defer c.cond.L.Unlock()
		if exists || delay == ForceCESSyncTime {
			c.fastQueue.Add(ces)
		} else {
			c.standardQueue.Add(ces)
		}
		c.cond.Signal()

	})

}

func (c *Controller) enqueueCESReconciliation(cess []CESKey, delay time.Duration) {
	for _, ces := range cess {
		c.logger.Debug("Enqueueing CES (if not empty name)", logfields.CESName, ces.string())
		if ces.Name != "" {
			c.enqueuedAtLock.Lock()
			if c.enqueuedAt[ces].IsZero() {
				c.enqueuedAt[ces] = time.Now()
			}
			c.enqueuedAtLock.Unlock()
			c.addToQueue(ces, delay)
		}
	}
}

func (c *Controller) getAndResetCESProcessingDelay(ces CESKey) float64 {
	c.enqueuedAtLock.Lock()
	defer c.enqueuedAtLock.Unlock()
	enqueued, exists := c.enqueuedAt[ces]
	if !exists {
		return 0
	}
	if !enqueued.IsZero() {
		delay := time.Since(enqueued)
		c.enqueuedAt[ces] = time.Time{}
		return delay.Seconds()
	}
	return 0
}

// start the worker thread, reconciles the modified CESs with api-server
func (c *Controller) Start(ctx cell.HookContext) error {
	// Processing CES/CEP events:
	// CES or CEP event is retrieved and checked whether it is from a priority namespace
	// Event is added to the fast queue if the namespace was priority and to the standard queue otherwise

	// Processing queues:
	// The controller checks if the fast queue and standard queue are empty
	// If yes, it waits on signal
	// if no, it checks if fast queue is empty
	// If no, it takes element from the fast queue. Otherwise it takes element from the standard queue.
	// CES from the queue is reconciled with the k8s api-server
	// if error appears while reconciling and maximum number of retries for this element has not been reached, it is added to the appropriate queue.
	// if the error has not appeared or the maximum number of retries has been reached, the element is forgotten.

	c.logger.Info("Bootstrap ces controller")
	c.context, c.contextCancel = context.WithCancel(context.Background())
	defer utilruntime.HandleCrash()

	switch c.slicingMode {
	case identityMode, deprecatedIdentityMode:
		if c.slicingMode == deprecatedIdentityMode {
			c.logger.Warn(fmt.Sprintf("%v is deprecated and has been renamed. Please use %v instead", deprecatedIdentityMode, identityMode))
		}
		c.manager = newCESManagerIdentity(c.maxCEPsInCES, c.logger)

	case fcfsMode, deprecatedFcfsMode:
		if c.slicingMode == deprecatedFcfsMode {
			c.logger.Warn(fmt.Sprintf("%v is deprecated and has been renamed. Please use %v instead", deprecatedFcfsMode, fcfsMode))
		}
		c.manager = newCESManagerFcfs(c.maxCEPsInCES, c.logger)

	default:
		return fmt.Errorf("Invalid slicing mode: %s", c.slicingMode)
	}

	c.reconciler = newReconciler(c.context, c.clientset.CiliumV2alpha1(), c.manager, c.logger, c.ciliumEndpoint, c.ciliumEndpointSlice, c.metrics)

	c.initializeQueue()

	if err := c.syncCESsInLocalCache(ctx); err != nil {
		return err
	}

	c.Job.Add(
		job.OneShot("proc-ns-events", func(ctx context.Context, health cell.Health) error {
			return c.processNamespaceEvents(ctx)
		}),
	)

	filter = priorityFilter{
		ipToCepList: make(map[string][]coreCiliumEndpointInfo),
	}

	// Start the work pools processing CEP events only after syncing CES in local cache.
	c.wp = workerpool.New(3)
	c.wp.Submit("cilium-endpoints-updater", c.runCiliumEndpointsUpdater)
	c.wp.Submit("cilium-endpoint-slices-updater", c.runCiliumEndpointSliceUpdater)
	c.wp.Submit("cilium-nodes-updater", c.runCiliumNodesUpdater)

	c.logger.Info("Starting CES controller reconciler.")
	c.Job.Add(
		job.OneShot("proc-queues", func(ctx context.Context, health cell.Health) error {
			c.worker()
			return nil
		}),
	)

	return nil
}

func (c *Controller) Stop(ctx cell.HookContext) error {
	c.wp.Close()
	c.fastQueue.ShutDown()
	c.standardQueue.ShutDown()
	c.contextCancel()
	return nil
}

func (c *Controller) runCiliumEndpointsUpdater(ctx context.Context) error {
	for event := range c.ciliumEndpoint.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.Debug("Got Upsert Endpoint event", logfields.CEPName, event.Key.String())
			c.onEndpointUpdate(event.Object)
		case resource.Delete:
			c.logger.Debug("Got Delete Endpoint event", logfields.CEPName, event.Key.String())
			c.onEndpointDelete(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

func (c *Controller) runCiliumEndpointSliceUpdater(ctx context.Context) error {
	for event := range c.ciliumEndpointSlice.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			c.logger.Debug("Got Upsert Endpoint Slice event", logfields.CESName, event.Key.String())
			c.onSliceUpdate(event.Object)
		case resource.Delete:
			c.logger.Debug("Got Delete Endpoint Slice event", logfields.CESName, event.Key.String())
			c.onSliceDelete(event.Object)
		}
		event.Done(nil)
	}
	return nil
}

func (c *Controller) runCiliumNodesUpdater(ctx context.Context) error {
	ciliumNodesStore, err := c.ciliumNodes.Store(ctx)
	if err != nil {
		c.logger.Warn("Couldn't get CiliumNodes store", logfields.Error, err)
		return err
	}
	for event := range c.ciliumNodes.Events(ctx) {
		event.Done(nil)
		totalNodes := len(ciliumNodesStore.List())
		if c.rateLimit.updateRateLimiterWithNodes(totalNodes) {
			c.logger.Info("Updated CES controller workqueue configuration",
				logfields.WorkQueueQPSLimit, c.rateLimit.current.Limit,
				logfields.WorkQueueBurstLimit, c.rateLimit.current.Burst)
		}
	}
	return nil
}

// Sync all CESs from cesStore to manager cache.
// Note: CESs are synced locally before CES controller running and this is required.
func (c *Controller) syncCESsInLocalCache(ctx context.Context) error {
	store, err := c.ciliumEndpointSlice.Store(ctx)
	if err != nil {
		c.logger.Warn("Error getting CES Store", logfields.Error, err)
		return err
	}
	for _, ces := range store.List() {
		cesName := c.manager.initializeMappingForCES(ces)
		for _, cep := range ces.Endpoints {
			c.manager.initializeMappingCEPtoCES(&cep, ces.Namespace, cesName)
		}
	}
	c.logger.Debug("Successfully synced all CESs locally")
	return nil
}

// worker runs a worker thread that just dequeues items, processes them, and
// marks them done.
func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) rateLimitProcessing() {
	delay := c.rateLimit.getDelay()
	select {
	case <-c.context.Done():
	case <-time.After(delay):
	}
}

func (c *Controller) getQueue() workqueue.TypedRateLimitingInterface[CESKey] {
	c.cond.L.Lock()
	defer c.cond.L.Unlock()

	if c.fastQueue.Len() == 0 && c.standardQueue.Len() == 0 {
		c.cond.Wait()
	}

	if c.fastQueue.Len() == 0 {
		return c.standardQueue
	} else {
		return c.fastQueue
	}
}

func (c *Controller) processNextWorkItem() bool {
	c.rateLimitProcessing()
	queue := c.getQueue()
	key, quit := queue.Get()
	if quit {
		return false
	}
	defer queue.Done(key)

	c.logger.Debug("Processing CES", logfields.CESName, key.string())

	queueDelay := c.getAndResetCESProcessingDelay(key)
	err := c.reconciler.reconcileCES(CESName(key.Name))
	if queue == c.fastQueue {
		c.metrics.CiliumEndpointSliceQueueDelay.WithLabelValues(LabelQueueFast).Observe(queueDelay)
	} else {
		c.metrics.CiliumEndpointSliceQueueDelay.WithLabelValues(LabelQueueStandard).Observe(queueDelay)
	}
	if err != nil {
		c.metrics.CiliumEndpointSliceSyncTotal.WithLabelValues(LabelValueOutcomeFail).Inc()
	} else {
		c.metrics.CiliumEndpointSliceSyncTotal.WithLabelValues(LabelValueOutcomeSuccess).Inc()
	}

	c.handleErr(queue, err, key)

	return true
}

func (c *Controller) handleErr(queue workqueue.TypedRateLimitingInterface[CESKey], err error, key CESKey) {
	if err == nil {
		queue.Forget(key)
		return
	}

	if queue.NumRequeues(key) < maxRetries {
		time.AfterFunc(c.rateLimiter.When(key), func() {
			c.cond.L.Lock()
			defer c.cond.L.Unlock()
			queue.Add(key)
			c.cond.Signal()
		})
		return
	}

	// Drop the CES from queue, we maxed out retries.
	c.logger.Error("Dropping the CES from queue, exceeded maxRetries",
		logfields.CESName, key.string(),
		logfields.Error, err)
	queue.Forget(key)
}
