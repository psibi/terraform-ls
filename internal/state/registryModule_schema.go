package state

import (
	"fmt"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-ls/internal/registry"
	tfaddr "github.com/hashicorp/terraform-registry-address"
)

type RegistryModuleMetadataSchema struct {
	Source  tfaddr.ModuleSourceRegistry
	Version *version.Version
	Inputs  []registry.Input
	Outputs []registry.Output
}

func (s *RegistryModuleMetadataStore) Exists(sourceAddr tfaddr.ModuleSourceRegistry, constraint version.Constraints) (bool, error) {
	txn := s.db.Txn(false)

	iter, _ := txn.Get(s.tableName, "id")
	for obj := iter.Next(); obj != nil; obj = iter.Next() {
		p := obj.(*RegistryModuleMetadataSchema)
		if constraint.Check(p.Version) {
			return true, nil
		}
	}

	return false, nil
}

func (s *RegistryModuleMetadataStore) Cache(sourceAddr tfaddr.ModuleSourceRegistry, modVer *version.Version, inputs []registry.Input, outputs []registry.Output) error {
	txn := s.db.Txn(true)
	defer txn.Abort()

	obj, err := txn.First(s.tableName, "id", sourceAddr, modVer)
	if err != nil {
		return err
	}
	if obj != nil {
		return &AlreadyExistsError{
			Idx: fmt.Sprintf("%s@%v", sourceAddr, modVer),
		}
	}

	thing := &RegistryModuleMetadataSchema{
		Source:  sourceAddr,
		Version: modVer,
		Inputs:  inputs,
		Outputs: outputs,
	}

	err = txn.Insert(s.tableName, thing)
	if err != nil {
		return err
	}

	txn.Commit()
	return nil
}
