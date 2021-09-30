// Code generated by go-swagger; DO NOT EDIT.

package p_cloud_cloud_connections

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"

	strfmt "github.com/go-openapi/strfmt"

	models "github.com/IBM-Cloud/power-go-client/power/models"
)

// NewPcloudCloudconnectionsPutParams creates a new PcloudCloudconnectionsPutParams object
// with the default values initialized.
func NewPcloudCloudconnectionsPutParams() *PcloudCloudconnectionsPutParams {
	var ()
	return &PcloudCloudconnectionsPutParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewPcloudCloudconnectionsPutParamsWithTimeout creates a new PcloudCloudconnectionsPutParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewPcloudCloudconnectionsPutParamsWithTimeout(timeout time.Duration) *PcloudCloudconnectionsPutParams {
	var ()
	return &PcloudCloudconnectionsPutParams{

		timeout: timeout,
	}
}

// NewPcloudCloudconnectionsPutParamsWithContext creates a new PcloudCloudconnectionsPutParams object
// with the default values initialized, and the ability to set a context for a request
func NewPcloudCloudconnectionsPutParamsWithContext(ctx context.Context) *PcloudCloudconnectionsPutParams {
	var ()
	return &PcloudCloudconnectionsPutParams{

		Context: ctx,
	}
}

// NewPcloudCloudconnectionsPutParamsWithHTTPClient creates a new PcloudCloudconnectionsPutParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewPcloudCloudconnectionsPutParamsWithHTTPClient(client *http.Client) *PcloudCloudconnectionsPutParams {
	var ()
	return &PcloudCloudconnectionsPutParams{
		HTTPClient: client,
	}
}

/*PcloudCloudconnectionsPutParams contains all the parameters to send to the API endpoint
for the pcloud cloudconnections put operation typically these are written to a http.Request
*/
type PcloudCloudconnectionsPutParams struct {

	/*Body
	  Parameters to update a Cloud Connection

	*/
	Body *models.CloudConnectionUpdate
	/*CloudConnectionID
	  Cloud Connection ID

	*/
	CloudConnectionID string
	/*CloudInstanceID
	  Cloud Instance ID of a PCloud Instance

	*/
	CloudInstanceID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the pcloud cloudconnections put params
func (o *PcloudCloudconnectionsPutParams) WithTimeout(timeout time.Duration) *PcloudCloudconnectionsPutParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the pcloud cloudconnections put params
func (o *PcloudCloudconnectionsPutParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the pcloud cloudconnections put params
func (o *PcloudCloudconnectionsPutParams) WithContext(ctx context.Context) *PcloudCloudconnectionsPutParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the pcloud cloudconnections put params
func (o *PcloudCloudconnectionsPutParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the pcloud cloudconnections put params
func (o *PcloudCloudconnectionsPutParams) WithHTTPClient(client *http.Client) *PcloudCloudconnectionsPutParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the pcloud cloudconnections put params
func (o *PcloudCloudconnectionsPutParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the pcloud cloudconnections put params
func (o *PcloudCloudconnectionsPutParams) WithBody(body *models.CloudConnectionUpdate) *PcloudCloudconnectionsPutParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the pcloud cloudconnections put params
func (o *PcloudCloudconnectionsPutParams) SetBody(body *models.CloudConnectionUpdate) {
	o.Body = body
}

// WithCloudConnectionID adds the cloudConnectionID to the pcloud cloudconnections put params
func (o *PcloudCloudconnectionsPutParams) WithCloudConnectionID(cloudConnectionID string) *PcloudCloudconnectionsPutParams {
	o.SetCloudConnectionID(cloudConnectionID)
	return o
}

// SetCloudConnectionID adds the cloudConnectionId to the pcloud cloudconnections put params
func (o *PcloudCloudconnectionsPutParams) SetCloudConnectionID(cloudConnectionID string) {
	o.CloudConnectionID = cloudConnectionID
}

// WithCloudInstanceID adds the cloudInstanceID to the pcloud cloudconnections put params
func (o *PcloudCloudconnectionsPutParams) WithCloudInstanceID(cloudInstanceID string) *PcloudCloudconnectionsPutParams {
	o.SetCloudInstanceID(cloudInstanceID)
	return o
}

// SetCloudInstanceID adds the cloudInstanceId to the pcloud cloudconnections put params
func (o *PcloudCloudconnectionsPutParams) SetCloudInstanceID(cloudInstanceID string) {
	o.CloudInstanceID = cloudInstanceID
}

// WriteToRequest writes these params to a swagger request
func (o *PcloudCloudconnectionsPutParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	// path param cloud_connection_id
	if err := r.SetPathParam("cloud_connection_id", o.CloudConnectionID); err != nil {
		return err
	}

	// path param cloud_instance_id
	if err := r.SetPathParam("cloud_instance_id", o.CloudInstanceID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}