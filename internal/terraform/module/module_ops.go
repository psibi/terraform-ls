package module

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	// "encoding/json"
	"fmt"
	"log"

	"github.com/hashicorp/go-version"
	"github.com/hashicorp/hcl-lang/lang"
	"github.com/hashicorp/terraform-ls/internal/decoder"
	ilsp "github.com/hashicorp/terraform-ls/internal/lsp"
	"github.com/hashicorp/terraform-ls/internal/state"
	"github.com/hashicorp/terraform-ls/internal/terraform/datadir"
	op "github.com/hashicorp/terraform-ls/internal/terraform/module/operation"
	"github.com/hashicorp/terraform-ls/internal/terraform/parser"
	tfaddr "github.com/hashicorp/terraform-registry-address"
	"github.com/hashicorp/terraform-schema/earlydecoder"
	"github.com/hashicorp/terraform-schema/module"
	tfschema "github.com/hashicorp/terraform-schema/schema"
)

type DeferFunc func(opError error)

type ModuleOperation struct {
	ModulePath string
	Type       op.OpType
	Defer      DeferFunc

	doneCh chan struct{}
}

func NewModuleOperation(modPath string, typ op.OpType) ModuleOperation {
	return ModuleOperation{
		ModulePath: modPath,
		Type:       typ,
		doneCh:     make(chan struct{}, 1),
	}
}

func (mo ModuleOperation) markAsDone() {
	mo.doneCh <- struct{}{}
	close(mo.doneCh)
}

func (mo ModuleOperation) done() <-chan struct{} {
	return mo.doneCh
}

func GetTerraformVersion(ctx context.Context, modStore *state.ModuleStore, modPath string) error {
	mod, err := modStore.ModuleByPath(modPath)
	if err != nil {
		return err
	}

	err = modStore.SetTerraformVersionState(modPath, op.OpStateLoading)
	if err != nil {
		return err
	}
	defer modStore.SetTerraformVersionState(modPath, op.OpStateLoaded)

	tfExec, err := TerraformExecutorForModule(ctx, mod.Path)
	if err != nil {
		sErr := modStore.UpdateTerraformVersion(modPath, nil, nil, err)
		if err != nil {
			return sErr
		}
		return err
	}

	v, pv, err := tfExec.Version(ctx)
	pVersions := providerVersions(pv)

	sErr := modStore.UpdateTerraformVersion(modPath, v, pVersions, err)
	if sErr != nil {
		return sErr
	}

	ipErr := modStore.UpdateInstalledProviders(modPath, pVersions)
	if ipErr != nil {
		return ipErr
	}

	return err
}

func providerVersions(pv map[string]*version.Version) map[tfaddr.Provider]*version.Version {
	m := make(map[tfaddr.Provider]*version.Version, 0)

	for rawAddr, v := range pv {
		pAddr, err := tfaddr.ParseRawProviderSourceString(rawAddr)
		if err != nil {
			// skip unparsable address
			continue
		}
		if pAddr.IsLegacy() {
			// TODO: check for migrations via Registry API?
		}
		m[pAddr] = v
	}

	return m
}

func ObtainSchema(ctx context.Context, modStore *state.ModuleStore, schemaStore *state.ProviderSchemaStore, modPath string) error {
	mod, err := modStore.ModuleByPath(modPath)
	if err != nil {
		return err
	}

	tfExec, err := TerraformExecutorForModule(ctx, mod.Path)
	if err != nil {
		sErr := modStore.FinishProviderSchemaLoading(modPath, err)
		if sErr != nil {
			return sErr
		}
		return err
	}

	ps, err := tfExec.ProviderSchemas(ctx)
	if err != nil {
		sErr := modStore.FinishProviderSchemaLoading(modPath, err)
		if sErr != nil {
			return sErr
		}
		return err
	}

	installedProviders := make(map[tfaddr.Provider]*version.Version, 0)

	for rawAddr, pJsonSchema := range ps.Schemas {
		pAddr, err := tfaddr.ParseRawProviderSourceString(rawAddr)
		if err != nil {
			// skip unparsable address
			continue
		}

		installedProviders[pAddr] = nil

		if pAddr.IsLegacy() {
			// TODO: check for migrations via Registry API?
		}

		pSchema := tfschema.ProviderSchemaFromJson(pJsonSchema, pAddr)

		err = schemaStore.AddLocalSchema(modPath, pAddr, pSchema)
		if err != nil {
			return err
		}
	}

	return modStore.UpdateInstalledProviders(modPath, installedProviders)
}

func ParseModuleConfiguration(fs ReadOnlyFS, modStore *state.ModuleStore, modPath string) error {
	err := modStore.SetModuleParsingState(modPath, op.OpStateLoading)
	if err != nil {
		return err
	}

	files, diags, err := parser.ParseModuleFiles(fs, modPath)

	sErr := modStore.UpdateParsedModuleFiles(modPath, files, err)
	if sErr != nil {
		return sErr
	}

	sErr = modStore.UpdateModuleDiagnostics(modPath, diags)
	if sErr != nil {
		return sErr
	}

	return err
}

func ParseVariables(fs ReadOnlyFS, modStore *state.ModuleStore, modPath string) error {
	err := modStore.SetVarsParsingState(modPath, op.OpStateLoading)
	if err != nil {
		return err
	}

	files, diags, err := parser.ParseVariableFiles(fs, modPath)

	sErr := modStore.UpdateParsedVarsFiles(modPath, files, err)
	if sErr != nil {
		return sErr
	}

	sErr = modStore.UpdateVarsDiagnostics(modPath, diags)
	if sErr != nil {
		return sErr
	}

	return err
}

func ParseModuleManifest(fs ReadOnlyFS, modStore *state.ModuleStore, modPath string) error {
	err := modStore.SetModManifestState(modPath, op.OpStateLoading)
	if err != nil {
		return err
	}

	manifestPath, ok := datadir.ModuleManifestFilePath(fs, modPath)
	if !ok {
		err := fmt.Errorf("%s: manifest file does not exist", modPath)
		sErr := modStore.UpdateModManifest(modPath, nil, err)
		if sErr != nil {
			return sErr
		}
		return err
	}

	mm, err := datadir.ParseModuleManifestFromFile(manifestPath)
	if err != nil {
		err := fmt.Errorf("failed to parse manifest: %w", err)
		sErr := modStore.UpdateModManifest(modPath, nil, err)
		if sErr != nil {
			return sErr
		}
		return err
	}

	sErr := modStore.UpdateModManifest(modPath, mm, err)

	if sErr != nil {
		return sErr
	}
	return err
}

func GetModuleMetadataFromRegistry(ctx context.Context, modStore *state.ModuleStore, schema *state.ProviderSchemaStore, modPath string, logger *log.Logger) error {
	// TODO: loop over module calls
	logger.Printf("OpTypeGetModuleMetadataFromRegistry Getting module calls for %v", modPath)
	calls, err := modStore.ModuleCalls(modPath)
	if err != nil {
		logger.Printf("Err Modulecalls: %v", err)
		return nil
	}

	logger.Printf("OpTypeGetModuleMetadataFromRegistry Found %v module calls installed for", len(calls.Installed))
	logger.Printf("OpTypeGetModuleMetadataFromRegistry Found %v module calls decalred for", len(calls.Declared))

	var providers []tfaddr.Provider
	for _, c := range calls.Installed {
		logger.Printf("SourceAddr: %v::%v::%v::%v", c.SourceAddr, c.LocalName, c.Path, c.Version)
		p, err := tfaddr.ParseRawProviderSourceString(c.SourceAddr)
		if err != nil {
			logger.Printf("Err SourceAddr: %v", err)
			continue
		}

		providers = append(providers, p)
	}

	for _, c := range calls.Declared {
		logger.Printf("SourceAddr: %v::%v::%v::%v", c.SourceAddr, c.LocalName, c.LocalName, c.Version)
		p, err := tfaddr.ParseRawProviderSourceString(c.SourceAddr)
		if err != nil {
			logger.Printf("Err SourceAddr: %v", err)
			continue
		}

		providers = append(providers, p)
	}

	for _, provider := range providers {
		logger.Printf("Provider: %v::%v::%v FQDN:%v", provider.Namespace, provider.Type, provider.Hostname, provider.String())
		logger.Printf("Provider: %v", provider.ForDisplay())

		// TODO: check if that address was already cached. if cached, return

		// get module data from tfregistry
		url := fmt.Sprintf("https://registry.terraform.io/v1/modules/%s", provider.String())
		logger.Printf("Provider: %v", url)
		resp, err := http.Get(url)
		if err != nil {
			continue
		}

		var response TerraformRegistryModule
		err = json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			continue
		}
		logger.Printf("Provider: %v", response.Root.Inputs)

		// TODO: if not, cache it
	}

	return nil
}

func LoadModuleMetadata(modStore *state.ModuleStore, modPath string) error {
	err := modStore.SetMetaState(modPath, op.OpStateLoading)
	if err != nil {
		return err
	}

	mod, err := modStore.ModuleByPath(modPath)
	if err != nil {
		return err
	}

	var mErr error
	meta, diags := earlydecoder.LoadModule(mod.Path, mod.ParsedModuleFiles.AsMap())
	if len(diags) > 0 {
		mErr = diags
	}

	providerRequirements := make(map[tfaddr.Provider]version.Constraints, len(meta.ProviderRequirements))
	for pAddr, pvc := range meta.ProviderRequirements {
		// TODO: check pAddr for migrations via Registry API?
		providerRequirements[pAddr] = pvc
	}
	meta.ProviderRequirements = providerRequirements

	providerRefs := make(map[module.ProviderRef]tfaddr.Provider, len(meta.ProviderReferences))
	for localRef, pAddr := range meta.ProviderReferences {
		// TODO: check pAddr for migrations via Registry API?
		providerRefs[localRef] = pAddr
	}
	meta.ProviderReferences = providerRefs

	sErr := modStore.UpdateMetadata(modPath, meta, mErr)
	if sErr != nil {
		return sErr
	}
	return mErr
}

func DecodeReferenceTargets(ctx context.Context, modStore *state.ModuleStore, schemaReader state.SchemaReader, modPath string) error {
	err := modStore.SetReferenceTargetsState(modPath, op.OpStateLoading)
	if err != nil {
		return err
	}

	d, err := decoder.NewDecoder(ctx, &decoder.PathReader{
		ModuleReader: modStore,
		SchemaReader: schemaReader,
	}).Path(lang.Path{
		Path:       modPath,
		LanguageID: ilsp.Terraform.String(),
	})
	if err != nil {
		return err
	}
	targets, rErr := d.CollectReferenceTargets()

	targets = append(targets, builtinReferences(modPath)...)

	sErr := modStore.UpdateReferenceTargets(modPath, targets, rErr)
	if sErr != nil {
		return sErr
	}

	return rErr
}

func DecodeReferenceOrigins(ctx context.Context, modStore *state.ModuleStore, schemaReader state.SchemaReader, modPath string) error {
	err := modStore.SetReferenceOriginsState(modPath, op.OpStateLoading)
	if err != nil {
		return err
	}

	d := decoder.NewDecoder(ctx, &decoder.PathReader{
		ModuleReader: modStore,
		SchemaReader: schemaReader,
	})

	moduleDecoder, err := d.Path(lang.Path{
		Path:       modPath,
		LanguageID: ilsp.Terraform.String(),
	})
	if err != nil {
		return err
	}

	origins, rErr := moduleDecoder.CollectReferenceOrigins()

	sErr := modStore.UpdateReferenceOrigins(modPath, origins, rErr)
	if sErr != nil {
		return sErr
	}

	return rErr
}

func DecodeVarsReferences(ctx context.Context, modStore *state.ModuleStore, schemaReader state.SchemaReader, modPath string) error {
	err := modStore.SetVarsReferenceOriginsState(modPath, op.OpStateLoading)
	if err != nil {
		return err
	}

	d := decoder.NewDecoder(ctx, &decoder.PathReader{
		ModuleReader: modStore,
		SchemaReader: schemaReader,
	})

	varsDecoder, err := d.Path(lang.Path{
		Path:       modPath,
		LanguageID: ilsp.Tfvars.String(),
	})
	if err != nil {
		return err
	}

	origins, rErr := varsDecoder.CollectReferenceOrigins()
	sErr := modStore.UpdateVarsReferenceOrigins(modPath, origins, rErr)
	if sErr != nil {
		return sErr
	}

	return rErr
}

type TerraformRegistryModule struct {
	ID              string    `json:"id"`
	Owner           string    `json:"owner"`
	Namespace       string    `json:"namespace"`
	Name            string    `json:"name"`
	Version         string    `json:"version"`
	Provider        string    `json:"provider"`
	ProviderLogoURL string    `json:"provider_logo_url"`
	Description     string    `json:"description"`
	Source          string    `json:"source"`
	Tag             string    `json:"tag"`
	PublishedAt     time.Time `json:"published_at"`
	Downloads       int       `json:"downloads"`
	Verified        bool      `json:"verified"`
	Root            struct {
		Path   string `json:"path"`
		Name   string `json:"name"`
		Readme string `json:"readme"`
		Empty  bool   `json:"empty"`
		Inputs []struct {
			Name        string `json:"name"`
			Type        string `json:"type"`
			Description string `json:"description"`
			Default     string `json:"default"`
			Required    bool   `json:"required"`
		} `json:"inputs"`
		Outputs []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"outputs"`
		Dependencies         []interface{} `json:"dependencies"`
		ProviderDependencies []struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			Source    string `json:"source"`
			Version   string `json:"version"`
		} `json:"provider_dependencies"`
		Resources []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"resources"`
	} `json:"root"`
	Submodules []struct {
		Path   string `json:"path"`
		Name   string `json:"name"`
		Readme string `json:"readme"`
		Empty  bool   `json:"empty"`
		Inputs []struct {
			Name        string `json:"name"`
			Type        string `json:"type"`
			Description string `json:"description"`
			Default     string `json:"default"`
			Required    bool   `json:"required"`
		} `json:"inputs"`
		Outputs []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"outputs"`
		Dependencies         []interface{} `json:"dependencies"`
		ProviderDependencies []struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			Source    string `json:"source"`
			Version   string `json:"version"`
		} `json:"provider_dependencies"`
		Resources []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"resources"`
	} `json:"submodules"`
	Examples []struct {
		Path    string        `json:"path"`
		Name    string        `json:"name"`
		Readme  string        `json:"readme"`
		Empty   bool          `json:"empty"`
		Inputs  []interface{} `json:"inputs"`
		Outputs []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"outputs"`
		Dependencies []struct {
			Name    string `json:"name"`
			Source  string `json:"source"`
			Version string `json:"version"`
		} `json:"dependencies"`
		ProviderDependencies []struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			Source    string `json:"source"`
			Version   string `json:"version"`
		} `json:"provider_dependencies"`
		Resources []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"resources"`
	} `json:"examples"`
	Providers []string `json:"providers"`
	Versions  []string `json:"versions"`
}
