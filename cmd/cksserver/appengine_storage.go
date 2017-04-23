package main

import (
	"encoding/hex"

	"github.com/continusec/verifiabledatastructures"
	"github.com/golang/protobuf/proto"
	"github.com/qedus/nds"
	"golang.org/x/net/context"
	"google.golang.org/appengine/datastore"
)

type AppEngineStorage struct{}

type dsBytes struct {
	Message []byte
}

// ExecuteReadOnly executes a read only query
func (ae *AppEngineStorage) ExecuteReadOnly(ctx context.Context, namespace []byte, f func(ctx context.Context, db verifiabledatastructures.KeyReader) error) error {
	return f(ctx, &krw{ns: datastore.NewKey(ctx, "vdb", hex.EncodeToString(namespace), 0, nil)})
}

// ExecuteUpdate executes an update query
func (ae *AppEngineStorage) ExecuteUpdate(ctx context.Context, namespace []byte, f func(ctx context.Context, db verifiabledatastructures.KeyWriter) error) error {
	return nds.RunInTransaction(ctx, func(ctx context.Context) error {
		return f(ctx, &krw{ns: datastore.NewKey(ctx, "vdb", hex.EncodeToString(namespace), 0, nil)})
	}, &datastore.TransactionOptions{
		Attempts: 10,
		XG:       false, // our namesapce should be the entity group at all times
	})
}

type krw struct {
	ns *datastore.Key
}

func (k *krw) Get(ctx context.Context, bucket, key []byte, m proto.Message) error {
	var rv dsBytes
	err := nds.Get(ctx, datastore.NewKey(ctx, "vdb", hex.EncodeToString(key), 0, datastore.NewKey(ctx, "vdb", hex.EncodeToString(bucket), 0, k.ns)), &rv)
	if err != nil {
		return err
	}
	return proto.Unmarshal(rv.Message, m)
}

func (k *krw) Set(ctx context.Context, bucket, key []byte, m proto.Message) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	_, err = nds.Put(ctx, datastore.NewKey(ctx, "vdb", hex.EncodeToString(key), 0, datastore.NewKey(ctx, "vdb", hex.EncodeToString(bucket), 0, k.ns)), &dsBytes{
		Message: b,
	})
	return err
}
