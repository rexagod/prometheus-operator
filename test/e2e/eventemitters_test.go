// Copyright 2023 The prometheus-operator Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package e2e

import (
	"context"
	"reflect"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"

	monv1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	monitoringv1alpha1 "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1alpha1"
)

const errUpdateInvalidResource = "expected error when updating %s/%s with invalid values"
const invalidConfigurationReason = "InvalidConfiguration"

func TestEventEmitters(t *testing.T) {
	testCtx := framework.NewTestCtx(t)
	defer testCtx.Cleanup(t)

	operatorNamespace := framework.CreateNamespace(context.Background(), t, testCtx)
	framework.SetupPrometheusRBAC(context.Background(), t, testCtx, operatorNamespace)
	_, err := framework.CreateOrUpdatePrometheusOperator(
		context.Background(),
		operatorNamespace,
		nil,
		nil,
		nil,
		nil,
		false,
		true,
		true,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Create an invalid AlertmanagerConfig.
	amcfg, err := framework.CreateAlertmanagerConfig(context.Background(), operatorNamespace, "invalid-alertmanager-config")
	if err != nil {
		t.Fatal(err)
	}
	amcfg.Spec.Receivers = []monitoringv1alpha1.Receiver{
		{
			Name: "test",
			PagerDutyConfigs: []monitoringv1alpha1.PagerDutyConfig{
				{
					URL: "not:/a.valid.url",
				},
			},
		},
	}
	_, err = framework.MonClientV1alpha1.AlertmanagerConfigs(operatorNamespace).Create(context.Background(), amcfg, metav1.CreateOptions{})
	if err == nil {
		t.Fatalf(errUpdateInvalidResource, amcfg.Kind, amcfg.Name)
	}

	// Create an invalid PodMonitor.
	pm := framework.MakeBasicPodMonitor("invalid-pod-monitor")
	pm.Spec.PodMetricsEndpoints[0].Port = "not-a-number"
	_, err = framework.MonClientV1.PodMonitors(operatorNamespace).Create(context.Background(), pm, metav1.CreateOptions{})
	if err == nil {
		t.Fatalf(errUpdateInvalidResource, pm.Kind, pm.Name)
	}

	// Create an invalid Probe.
	p := framework.MakeBasicStaticProbe("invalid-probe", "", nil)
	p.Spec.Interval = "not-a-duration"
	_, err = framework.MonClientV1.Probes(operatorNamespace).Create(context.Background(), p, metav1.CreateOptions{})
	if err == nil {
		t.Fatalf(errUpdateInvalidResource, p.Kind, p.Name)
	}

	// Create an invalid ServiceMonitor.
	sm := framework.MakeBasicServiceMonitor("invalid-service-monitor")
	sm.Spec.Endpoints[0].Port = "not-a-number"
	_, err = framework.MonClientV1.ServiceMonitors(operatorNamespace).Create(context.Background(), sm, metav1.CreateOptions{})
	if err == nil {
		t.Fatalf(errUpdateInvalidResource, sm.Kind, sm.Name)
	}

	// Create an invalid ScrapeConfig.
	sc := framework.MakeBasicScrapeConfig(operatorNamespace, "invalid-scrape-config")
	invalidMetricsPath := "not-a-path"
	sc.Spec.MetricsPath = &invalidMetricsPath
	_, err = framework.MonClientV1alpha1.ScrapeConfigs(operatorNamespace).Create(context.Background(), sc, metav1.CreateOptions{})
	if err == nil {
		t.Fatalf(errUpdateInvalidResource, sc.Kind, sc.Name)
	}

	// Create an invalid PrometheusRule.
	pr := framework.MakeBasicRule(operatorNamespace, "invalid-prometheus-rule", []monv1.RuleGroup{
		{
			Name: "invalid-rule-group",
			Rules: []monv1.Rule{
				{
					Alert: "invalid-alert",
					Expr:  intstr.IntOrString{Type: intstr.String, StrVal: "invalid-expression"},
				},
			},
		},
	})
	_, err = framework.MonClientV1.PrometheusRules(operatorNamespace).Create(context.Background(), pr, metav1.CreateOptions{})
	if err == nil {
		t.Fatalf(errUpdateInvalidResource, pr.Kind, pr.Name)
	}

	// Setup informers for events.
	invalidKinds := []string{
		"AlertmanagerConfig",
		"PodMonitor",
		"Probe",
		"ServiceMonitor",
		"ScrapeConfig",
		"PrometheusRule",
	}
	invalidKindsGot := []string{}
	eventsFactory := informers.NewSharedInformerFactory(framework.KubeClient, 0)
	eventsInformer := eventsFactory.Core().V1().Events().Informer()
	_, err = eventsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			event := obj.(*v1.Event)
			t.Logf("Received event: %s/%s: %s", event.Namespace, event.Name, event.Message)
			if event.Reason != invalidConfigurationReason {
				return
			}
			switch event.InvolvedObject.Kind {
			case "AlertmanagerConfig":
				if event.InvolvedObject.Name != amcfg.Name {
					return
				}
				invalidKindsGot = append(invalidKindsGot, "AlertmanagerConfig")
			case "PodMonitor":
				if event.InvolvedObject.Name != pm.Name {
					return
				}
				invalidKindsGot = append(invalidKindsGot, "PodMonitor")
			case "Probe":
				if event.InvolvedObject.Name != p.Name {
					return
				}
				invalidKindsGot = append(invalidKindsGot, "Probe")
			case "ServiceMonitor":
				if event.InvolvedObject.Name != sm.Name {
					return
				}
				invalidKindsGot = append(invalidKindsGot, "ServiceMonitor")
			case "ScrapeConfig":
				if event.InvolvedObject.Name != sc.Name {
					return
				}
				invalidKindsGot = append(invalidKindsGot, "ScrapeConfig")
			case "PrometheusRule":
				if event.InvolvedObject.Name != pr.Name {
					return
				}
				invalidKindsGot = append(invalidKindsGot, "PrometheusRule")
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Start informers.
	stopCh := make(chan struct{})
	eventsInformer.Run(stopCh)
	go func() {
		for range time.After(10 * time.Second) {
			stopCh <- struct{}{}
		}
	}()

	// Compare.
	<-stopCh
	if reflect.DeepEqual(invalidKinds, invalidKindsGot) {
		t.Fatalf("expected invalid kinds to be %v, got %v", invalidKinds, invalidKindsGot)
	}
}
