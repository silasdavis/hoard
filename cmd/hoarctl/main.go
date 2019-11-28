package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"

	"github.com/monax/hoard/v6/api"

	cli "github.com/jawher/mow.cli"
	"github.com/monax/hoard/v6/cmd"
	"github.com/monax/hoard/v6/config"
	"github.com/monax/hoard/v6/grant"
	"github.com/monax/hoard/v6/reference"
	"github.com/monax/hoard/v6/server"
	"google.golang.org/grpc"
)

const (
	addrOpt string = "The address of the data to retrieve as base64-encoded string."
	keyOpt  string = "The ID of the symmetric secret to use."
	saltOpt string = "Token to use for encryption and decryption. " +
		"Will be parsed as base64 encoded string if this is possible, " +
		"otherwise will be interpreted as the bytes of the string itself."
	secretOpt string = "The secret key to decrypt the data with as base64-encoded string."
	chunkOpt  string = "Size in bytes to chunk upload data at."
	fileOpt   string = "File to read"

	chunkSize = 64 * 1024 // 64 Kb
	grpcLimit = 4 * 1024 * 1024
)

// Client scopes the available hoard clients
type Client struct {
	cleartext  api.CleartextClient
	encryption api.EncryptionClient
	grant      api.GrantClient
	storage    api.StorageClient
	documents  api.DocumentClient
}

func main() {
	hoarctlApp := cli.App("hoarctl",
		"Command line interface to the hoard daemon a content-addressed "+
			"deterministically encrypted blob storage system")

	dialURL := hoarctlApp.StringOpt("a address", config.DefaultListenAddress,
		"local address on which hoard is listening encoded as a URL with the "+
			"network protocol as the scheme, for example 'tcp://localhost:54192' "+
			"or 'unix:///tmp/hoard.sock'")

	client := Client{}
	var conn *grpc.ClientConn

	hoarctlApp.Before = func() {
		netProtocol, localAddress, err := server.SplitListenURL(*dialURL)

		conn, err = grpc.Dial(*dialURL,
			grpc.WithInsecure(),
			// We have to bugger around with this so we can dial an arbitrary net.Conn
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return net.Dial(netProtocol, localAddress)
			}))
		if err != nil {
			fatalf("Could not dial hoard server on %s: %v", *dialURL, err)
		}
		client.cleartext = api.NewCleartextClient(conn)
		client.encryption = api.NewEncryptionClient(conn)
		client.grant = api.NewGrantClient(conn)
		client.storage = api.NewStorageClient(conn)
		client.documents = api.NewDocumentClient(conn)
	}

	cmd.AddVersionCommand(hoarctlApp)

	hoarctlApp.Command("put", "Put some data read from STDIN into encrypted data store and return a reference on STDOUT", client.Put)
	hoarctlApp.Command("delete", "Delete data located at the address fed from STDIN", client.Delete)
	hoarctlApp.Command("get", "Get some data from encrypted data store and write it to STDOUT - must have the JSON reference to the "+
		"object passed in on STDIN (as generated by ref or put) or the ADDRESS and SECRET_KEY provided", client.Get)
	hoarctlApp.Command("stat", "Get information about the encrypted blob stored as an address from a reference passed in on STDIN "+
		"or passed as in as a single argument as a base64 encoded string", client.Stat)
	hoarctlApp.Command("insert", "Insert data from STDIN directly into store at its address which is written to STDOUT", client.Insert)
	hoarctlApp.Command("cat", "Retrieve the encrypted blob stored as an address from a reference passed in on STDIN or passed as in as "+
		"a single argument as a base64 encoded string", client.Cat)

	hoarctlApp.Command("ref", "Encrypt data from STDIN and return its reference", client.Ref)
	hoarctlApp.Command("encrypt", "Encrypt data from STDIN and output encrypted data on STDOUT", client.Encrypt)
	hoarctlApp.Command("decrypt", "Decrypt data from STDIN and output decrypted data on STDOUT", client.Decrypt)

	hoarctlApp.Command("upload", "Read a file and upload to Hoard with metadata", client.Upload)
	hoarctlApp.Command("download", "Download a file from Hoard with metadata", client.Download)

	hoarctlApp.Command("seal", "Seal some data read from STDIN and return grant on STDOUT", client.Seal)
	hoarctlApp.Command("unseal", "Unseal grant read from STDIN and print data to STDOUT", client.Unseal)
	hoarctlApp.Command("reseal", "Reseal grant read from STDIN and print new grant to STDOUT", client.Reseal)
	hoarctlApp.Command("putseal", "Put some data read from STDIN into encrypted data store and return a grant on STDOUT", client.PutSeal)
	hoarctlApp.Command("unsealget", "Unseal grant read from STDIN and print decrypted data to STDOUT", client.UnsealGet)

	hoarctlApp.Run(os.Args)
}

// extra cli options
func addStringOpt(cmd *cli.Cmd, arg, desc string) *string {
	opt := cmd.StringOpt(fmt.Sprintf("%s %s", string(arg[0]), arg), "", desc)
	cmd.Spec += fmt.Sprintf("[-%s | --%s]", string(arg[0]), arg)
	return opt
}

func addIntOpt(cmd *cli.Cmd, arg, desc string, def int) *int {
	opt := cmd.IntOpt(fmt.Sprintf("%s %s", string(arg[0]), arg), def, desc)
	cmd.Spec += fmt.Sprintf("[-%s | --%s]", string(arg[0]), arg)
	return opt
}

func validateChunkSize(cs int) {
	if cs == 0 {
		fatalf("Chunk size cannot be 0")
	} else if cs > grpcLimit {
		fatalf("Chunk size cannot be greater than 4Mb")
	}
}

func parseSalt(saltString *string) []byte {
	if saltString == nil {
		return nil
	}
	saltBytes, err := base64.StdEncoding.DecodeString(*saltString)
	if err == nil {
		return saltBytes
	}
	return ([]byte)(*saltString)
}

func jsonString(v interface{}) string {
	bs, err := json.Marshal(v)
	if err != nil {
		fatalf("Could not serialise '%s' to json: %v", err)
	}
	return string(bs)

}

func readData(f *os.File) []byte {
	data, err := ioutil.ReadAll(f)
	if err != nil {
		fatalf("Could not read bytes to store: %v", err)
	}
	return data
}

func openFile(file *string) (*os.File, error) {
	if file == nil || *file == "" {
		return nil, fmt.Errorf("no file given")
	}
	return os.Open(*file)
}

func readReference(address *string) *reference.Ref {
	ref := new(reference.Ref)
	if address != nil && *address != "" {
		ref.Address = readBase64(address)
		return ref
	}
	err := parseObject(os.Stdin, ref)
	if err != nil {
		fatalf("Could not read reference from STDIN: %v", err)
	}
	return ref
}

func readGrant() *grant.Grant {
	grt := new(grant.Grant)
	err := parseObject(os.Stdin, grt)
	if err != nil {
		fatalf("Could not read grant from STDIN: %v", err)
	}
	return grt
}

func parseObject(r io.Reader, o interface{}) error {
	bs, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}
	err = json.Unmarshal(bs, o)
	if err != nil {
		return err
	}
	return nil
}

func readBase64(base64String *string) []byte {
	if base64String == nil {
		return nil
	}
	secretKeyBytes, err := base64.StdEncoding.DecodeString(*base64String)
	if err != nil {
		fatalf("Could not decode '%s' as base64-encoded string", base64String)
	}
	return secretKeyBytes
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
