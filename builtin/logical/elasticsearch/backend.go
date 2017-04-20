package elasticsearch

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"sync"
	"strings"
	"net/http"
	"github.com/hashicorp/go-uuid"
	"encoding/json"
	"bytes"
	"time"
	"errors"
	"fmt"
	"io/ioutil"
	"encoding/base32"
)

func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	return Backend().Setup(conf)
}

func Backend() *framework.Backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),
		Paths: []*framework.Path{
			pathConfigRoot(&b),
			pathCredsCreate(&b),
		},
		Secrets: []*framework.Secret{
			secretCreds(&b),
		},
	}

	return b.Backend
}

type backend struct {
	*framework.Backend

	lock    sync.Mutex
}

func pathCredsCreate(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: "Name of the role",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathCredsCreateRead,
		},
	}
}


type CreateUserPayload struct {
	Password string `json:"password"`
	Roles []string `json:"roles"`
	Metadata map[string]interface{} `json:"metadata"`
}

type CreateUserResponse struct {
	User *CreateUserResponseUser `json:"user"`
}

type CreateUserResponseUser struct {
	Created bool `json:"created"`
}

// read a specific user role
func (b *backend) pathCredsCreateRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	fmt.Println(req.Data)
	fmt.Println(req)
	fmt.Println(req.Data)
	roleName := data.Get("name").(string)

	rootEntry, err := req.Storage.Get("config/root")
	if err != nil {
		return nil, err
	}

	var rc rootConfig

	if rootEntry.DecodeJSON(&rc) != nil {
		return nil, err
	}

	rbytes, err := uuid.GenerateRandomBytes(16)
	if err != nil {
		return nil, err
	}

	username := "vlt-" + strings.TrimRight(base32.StdEncoding.EncodeToString(rbytes), "=")

	userPassword, err := uuid.GenerateUUID()
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	encoder := json.NewEncoder(buf)

	err = encoder.Encode(&CreateUserPayload{
		Password: userPassword,
		Roles: []string{roleName},
		Metadata: map[string]interface{}{
			"vault_user": username,
		},
	})

	if err != nil {
		return nil, err
	}

	url := rc.Endpoint + "/_xpack/security/user/" + username

	fmt.Println("writing user to", url, buf.String())

	buf.Reset()

	fmt.Println("writing user to", url, buf.String())

	err = encoder.Encode(&CreateUserPayload{
		Password: userPassword,
		Roles: []string{roleName},
		Metadata: map[string]interface{}{
			"vault_user": username,
		},
	})

	if err != nil {
		return nil, err
	}

	createRequest, err := http.NewRequest(http.MethodPost, url, buf)
	if err != nil {
		return nil, err
	}

	createRequest.Header.Set("Content-Type", "application/json")
	createRequest.SetBasicAuth(rc.Username, rc.Password)

	createResponse, err := http.DefaultClient.Do(createRequest)
	if err != nil {
		return nil, err
	}

	if createResponse.StatusCode > 299 || createResponse.StatusCode < 200 {
		data, err := ioutil.ReadAll(createResponse.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("unexpected response: %v", string(data))
	}

	createUserResponse := new(CreateUserResponse)

	if err = json.NewDecoder(createResponse.Body).Decode(createUserResponse); err != nil {
		return nil, err
	}

	fmt.Println("read:", createResponse, createUserResponse)

	resp := b.Secret(secretCredsType).Response(map[string]interface{}{
		"endpoint": rc.Endpoint,
		"username": username,
		"password": userPassword,
	}, map[string]interface{}{
		"endpoint": rc.Endpoint,
		"username": username,
	})

	resp.Secret.TTL = 15 * time.Second

	return resp, nil
}

func pathConfigRoot(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/root",
		Fields: map[string]*framework.FieldSchema{
			"endpoint": &framework.FieldSchema{
				Type: framework.TypeString,
			},
			"username": &framework.FieldSchema{
				Type: framework.TypeString,
			},
			"password": &framework.FieldSchema{
				Type: framework.TypeString,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: pathConfigRootUpdate,
		},
	}
}

type rootConfig struct {
	Endpoint string `json:"endpoint"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func pathConfigRootUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	endpoint := data.Get("endpoint").(string)
	username := data.Get("username").(string)
	password := data.Get("password").(string)

	entry, err := logical.StorageEntryJSON("config/root", rootConfig{
		Username: username,
		Password: password,
		Endpoint: endpoint,
	})

	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(entry); err != nil {
		return nil, err
	}

	return nil, nil
}

var secretCredsType = "secretCredsType"

func secretCreds(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretCredsType,
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type: framework.TypeString,
			},
			"password": {
				Type: framework.TypeString,
			},
		},
		Renew: b.secretCredsRenew,
		Revoke: b.secretCredsRevoke,
	}
}

func (b *backend) secretCredsRenew(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	f := framework.LeaseExtend(60 * time.Second, 60 * time.Second, b.System())

	return f(req, data)
}

type DeleteUserResponse struct {
	Found bool `json:"found"`
}

func (b *backend) secretCredsRevoke(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rootEntry, err := req.Storage.Get("config/root")
	if err != nil {
		return nil, err
	}

	var rc rootConfig

	if rootEntry.DecodeJSON(&rc) != nil {
		return nil, err
	}

	usernameRaw, ok := req.Secret.InternalData["username"]
	if !ok {
		return nil, errors.New("secret is missing username internal data")
	}

	username, ok := usernameRaw.(string)
	if !ok {
		return nil, errors.New("username internal data is not a string")
	}

	endpointRaw, ok := req.Secret.InternalData["endpoint"]
	if !ok {
		return nil, errors.New("secret is missing endpoint internal data")
	}

	endpoint, ok := endpointRaw.(string)
	if !ok {
		return nil, errors.New("endpoint internal data is not a string")
	}

	deleteRequest, err := http.NewRequest(http.MethodDelete, endpoint + "/_xpack/security/user/" + username, nil)
	if err != nil {
		return nil, err
	}

	deleteRequest.SetBasicAuth(rc.Username, rc.Password)

	fmt.Println("deleting", deleteRequest)

	deleteResponse, err := http.DefaultClient.Do(deleteRequest)
	if err != nil {
		return nil, err
	}

	fmt.Println("deleted", deleteResponse)

	deleteUserResponse := new(DeleteUserResponse)
	if err = json.NewDecoder(deleteResponse.Body).Decode(deleteUserResponse); err != nil {
		return nil, err
	}

	fmt.Println("deleted:", deleteUserResponse)

	return nil, nil
}

var backendHelp = `
This is the Elasticsearch backend help.
`