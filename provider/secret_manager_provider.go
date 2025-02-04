package provider

import (
	"context"
	"fmt"
	"io/ioutil"
	"math"
	"time"

	"github.com/AliyunContainerService/ack-secret-manager/pkg/utils"
	kms "github.com/alibabacloud-go/kms-20160120/v2/client"
	oos "github.com/alibabacloud-go/oos-20190601/v4/client"
	"github.com/alibabacloud-go/tea/tea"
	sdkErr "github.com/aliyun/alibaba-cloud-sdk-go/sdk/errors"
	"k8s.io/klog/v2"
	"sigs.k8s.io/secrets-store-csi-driver/provider/v1alpha1"
)

const (
	REJECTED_THROTTLING           = "Rejected.Throttling"
	SERVICE_UNAVAILABLE_TEMPORARY = "ServiceUnavailableTemporary"
	INTERNAL_FAILURE              = "InternalFailure"
)

var (
	BACKOFF_DEFAULT_RETRY_INTERVAL = time.Second
	BACKOFF_DEFAULT_CAPACITY       = time.Duration(10) * time.Second
)

const (
	ObjectTypeKMS = "kms"
	ObjectTypeOOS = "oos"
)

type Limiter struct {
	Kms KmsLimiter
	OOS OosLimiter
}

var LimiterInstance Limiter

type SecretsManagerProvider struct {
	KmsClient *kms.Client
	OosClient *oos.Client
}

type SecretFile struct {
	Value    []byte
	Path     string
	FileMode int32
	UID      string
	Version  string
}

// Get the secret from KMS secrets manager.
func (p *SecretsManagerProvider) GetSecretValues(
	secretObjs []*SecretObject,
	curMap map[string]*v1alpha1.ObjectVersion,
) (v []*SecretValue, e error) {

	// Fetch each secret
	var values []*SecretValue
	for _, secObj := range secretObjs {

		// Don't re-fetch if we already have the current version.
		isCurrent, version, err := p.isCurrent(secObj, curMap)
		if err != nil {
			return nil, err
		}

		// If version is current, read it back in, otherwise pull it down
		var secret *SecretValue
		if isCurrent {
			secret, err = p.reloadSecret(secObj)
			if err != nil {
				return nil, err
			}

		} else { // Fetch the latest version.
			version, secret, err = p.fetchSecret(secObj)
			if err != nil {
				return nil, err
			}

		}
		values = append(values, secret) // Build up the slice of values
		//support individual json key value pairs based on jmesPath
		jsonSecrets, err := secret.getJsonSecrets()
		if err != nil {
			return nil, err
		}
		if len(jsonSecrets) > 0 {
			values = append(values, jsonSecrets...)
			// Update the version in the current version map.
			for _, jsonSecret := range jsonSecrets {
				jsonObj := jsonSecret.SecretObj
				curMap[jsonObj.GetFileName()] = &v1alpha1.ObjectVersion{
					Id:      jsonObj.GetFileName(),
					Version: version,
				}
			}
		}

		// Update the version in the current version map.
		curMap[secObj.GetFileName()] = &v1alpha1.ObjectVersion{
			Id:      secObj.GetFileName(),
			Version: version,
		}
	}

	return values, nil
}

func (p *SecretsManagerProvider) isCurrent(
	secObj *SecretObject,
	curMap map[string]*v1alpha1.ObjectVersion,
) (cur bool, ver string, e error) {

	// If we don't have this version, it is not current.
	curVer := curMap[secObj.GetFileName()]
	if curVer == nil {
		return false, "", nil
	}

	// If the secret is pinned to a version see if that is what we have.
	if len(secObj.ObjectVersion) > 0 {
		return curVer.Version == secObj.ObjectVersion, curVer.Version, nil
	}
	return
}

// Private helper to fetch a given secret.
//
// This method builds up the GetSecretValue request using the objectName from
// the request and any objectVersion or objectVersionLabel parameters.
func (smp *SecretsManagerProvider) fetchSecret(secObj *SecretObject) (ver string, val *SecretValue, e error) {
	waitTimeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	switch secObj.ObjectType {
	case ObjectTypeKMS, "":
		err := LimiterInstance.Kms.Wait(waitTimeoutCtx)
		if err != nil {
			return "", nil, err
		}
		if smp.KmsClient == nil {
			return "", nil, fmt.Errorf("kms client is empty")
		}
		return getKMSSecret(smp.KmsClient, secObj)
	case ObjectTypeOOS:
		err := LimiterInstance.OOS.Wait(waitTimeoutCtx)
		if err != nil {
			return "", nil, err
		}
		if smp.OosClient == nil {
			return "", nil, fmt.Errorf("oos client is empty")
		}
		return getOOSSecret(smp.OosClient, secObj)
	default:
		return "", nil, fmt.Errorf("Secret type  %s not support. Only support kms and oos", secObj.ObjectType)
	}
}

func getKMSSecret(c *kms.Client, secObj *SecretObject) (string, *SecretValue, error) {
	request := &kms.GetSecretValueRequest{
		SecretName: tea.String(secObj.ObjectName),
	}
	if secObj.ObjectVersion != "" {
		request.VersionId = tea.String(secObj.ObjectVersion)
	}
	if secObj.ObjectVersionLabel != "" {
		request.VersionStage = tea.String(secObj.ObjectVersionLabel)
	}
	response, err := c.GetSecretValue(request)
	if err != nil {
		klog.Error(err, "failed to get %s secret value from kms, err = %s", secObj.ObjectName, err.Error())
		if !judgeNeedRetry(err) {
			klog.Error(err, "failed to get secret value from kms", "key", secObj.ObjectName)
			return "", nil, fmt.Errorf("Failed fetching secret %s: %s", secObj.ObjectName, err.Error())
		} else {
			time.Sleep(getWaitTimeExponential(1))
			response, err = c.GetSecretValue(request)
			if err != nil {
				klog.Error(err, "failed to get secret value from kms", "key", secObj.ObjectName)
				return "", nil, fmt.Errorf("Failed fetching secret %s: %s", secObj.ObjectName, err.Error())
			}
		}
	}
	if *response.Body.SecretDataType == utils.BinaryType {
		klog.Error(err, "not support binary type yet", "key", secObj.ObjectName)
		return "", nil, fmt.Errorf("Secret type not support at %s: %s", secObj.ObjectName, err.Error())

	}

	return *response.Body.VersionId, &SecretValue{Value: []byte(*response.Body.SecretData), SecretObj: *secObj}, nil
}

func getOOSSecret(c *oos.Client, secObj *SecretObject) (string, *SecretValue, error) {
	request := &oos.GetSecretParameterRequest{
		Name:           tea.String(secObj.ObjectName),
		WithDecryption: tea.Bool(true),
	}
	response, err := c.GetSecretParameter(request)
	if err != nil {
		if !judgeNeedRetry(err) {
			klog.Error(err, "failed to get secret value from oos", "key", secObj.ObjectName)
			return "", nil, fmt.Errorf("Failed fetching secret %s: %s", secObj.ObjectName, err.Error())
		} else {
			time.Sleep(getWaitTimeExponential(1))
			response, err = c.GetSecretParameter(request)
			if err != nil {
				klog.Error(err, "failed to get secret value from oos", "key", secObj.ObjectName)
				return "", nil, fmt.Errorf("Failed fetching secret %s: %s", secObj.ObjectName, err.Error())
			}
		}
	}
	if *response.Body.Parameter.Value == utils.BinaryType {
		klog.Error(err, "not support binary type yet", "key", secObj.ObjectName)
		return "", nil, fmt.Errorf("Secret type not support at %s: %s", secObj.ObjectName, err.Error())

	}

	return "v1", &SecretValue{Value: []byte(*response.Body.Parameter.Value), SecretObj: *secObj}, nil
}

func judgeNeedRetry(err error) bool {
	respErr, is := err.(*sdkErr.ClientError)
	if is && (respErr.ErrorCode() == REJECTED_THROTTLING || respErr.ErrorCode() == SERVICE_UNAVAILABLE_TEMPORARY || respErr.ErrorCode() == INTERNAL_FAILURE) {
		return true
	}
	return false
}

func getWaitTimeExponential(retryTimes int) time.Duration {
	sleepInterval := time.Duration(math.Pow(2, float64(retryTimes))) * BACKOFF_DEFAULT_RETRY_INTERVAL
	if sleepInterval >= BACKOFF_DEFAULT_CAPACITY {
		return BACKOFF_DEFAULT_CAPACITY
	} else {
		return sleepInterval
	}
}

// Reload a secret from the file system.
func (p *SecretsManagerProvider) reloadSecret(secObj *SecretObject) (val *SecretValue, e error) {
	sValue, err := ioutil.ReadFile(secObj.GetMountPath())
	if err != nil {
		return nil, err
	}

	return &SecretValue{Value: sValue, SecretObj: *secObj}, nil
}
