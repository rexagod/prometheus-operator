package validation

import "k8s.io/apimachinery/pkg/runtime"

var xIsAlpha *uint8

func isAlpha() bool {
	return *xIsAlpha == 1
}

func resolve(obj interface{}, fields []string) (interface{}, error) {
	xIsAlphaValue := uint8(0)
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	alphaObj := unstructuredObj["alpha"]
	if alphaObj != nil {
		xIsAlphaValue = 1
		unstructuredObj = alphaObj.(map[string]interface{})
	}
	betaObj := unstructuredObj["beta"]
	if betaObj != nil {
		unstructuredObj = betaObj.(map[string]interface{})
	}
	for _, field := range fields {
		if obj == nil {
			return nil, nil
		}
		obj = unstructuredObj[field]
	}
	xIsAlpha = &xIsAlphaValue

	return obj, nil
}

func resolveList(obj interface{}, fields []string) ([]interface{}, error) {
	xIsAlphaValue := uint8(0)
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil, err
	}
	alphaObj := unstructuredObj["alpha"]
	if alphaObj != nil {
		xIsAlphaValue = 1
		unstructuredObj = alphaObj.(map[string]interface{})
	}
	betaObj := unstructuredObj["beta"]
	if betaObj != nil {
		unstructuredObj = betaObj.(map[string]interface{})
	}
	for _, field := range fields {
		if obj == nil {
			return nil, nil
		}
		obj = unstructuredObj[field]
	}
	xIsAlpha = &xIsAlphaValue

	return obj.([]interface{}), nil
}
