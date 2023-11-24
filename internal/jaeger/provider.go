// Copyright (c) Ultraviolet
// SPDX-License-Identifier: Apache-2.0
package jaeger

import (
	"context"
	"errors"
	"net/url"

	jaegerp "go.opentelemetry.io/contrib/propagators/jaeger"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.12.0"
)

var (
	errNoURL                     = errors.New("URL is empty")
	errNoSvcName                 = errors.New("Service Name is empty")
	errUnsupportedTraceURLScheme = errors.New("unsupported tracing url scheme")
)

// NewProvider initializes Jaeger TraceProvider.
func NewProvider(ctx context.Context, svcName, jaegerurl, instanceID string) (*tracesdk.TracerProvider, error) {
	if jaegerurl == "" {
		return nil, errNoURL
	}

	if svcName == "" {
		return nil, errNoSvcName
	}

	jurl, err := url.Parse(jaegerurl)
	if err != nil {
		return nil, err
	}

	var exporter *otlptrace.Exporter
	switch jurl.Scheme {
	case "http":
		exporter, err = otlptracehttp.New(ctx, otlptracehttp.WithEndpoint(jurl.Host), otlptracehttp.WithURLPath(jurl.Path), otlptracehttp.WithInsecure())
		if err != nil {
			return nil, err
		}
	case "https":
		exporter, err = otlptracehttp.New(ctx, otlptracehttp.WithEndpoint(jurl.Host), otlptracehttp.WithURLPath(jurl.Path))
		if err != nil {
			return nil, err
		}
	default:
		return nil, errUnsupportedTraceURLScheme
	}

	attributes := []attribute.KeyValue{
		semconv.ServiceNameKey.String(svcName),
		attribute.String("InstanceID", instanceID),
	}

	hostAttr, err := resource.New(ctx, resource.WithHost(), resource.WithOSDescription(), resource.WithContainer())
	if err != nil {
		return nil, err
	}
	attributes = append(attributes, hostAttr.Attributes()...)

	tp := tracesdk.NewTracerProvider(
		tracesdk.WithSampler(tracesdk.AlwaysSample()),
		tracesdk.WithBatcher(exporter),
		tracesdk.WithResource(resource.NewWithAttributes(
			semconv.SchemaURL,
			attributes...,
		)),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(jaegerp.Jaeger{})

	return tp, nil
}
