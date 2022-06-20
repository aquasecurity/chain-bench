package builders

import (
	"github.com/aquasecurity/chain-bench/internal/models"
	"github.com/aquasecurity/chain-bench/internal/utils"
)

type PackageRegistryBuilder struct {
	registry *models.PackageRegistry
}

func NewRegistryBuilder() *PackageRegistryBuilder {
	return &PackageRegistryBuilder{registry: &models.PackageRegistry{
		TwoFactorRequirementEnabled: utils.GetPtr(true),
		Packages: []*models.Package{{
			PackageType: utils.GetPtr("npm"),
			Visibility:  utils.GetPtr("private"),
			Repository:  &models.Repository{IsPrivate: utils.GetPtr(true)},
		}},
	}}
}

func (p *PackageRegistryBuilder) WithTwoFactorAuthenticationEnabled(enabled bool) *PackageRegistryBuilder {
	p.registry.TwoFactorRequirementEnabled = utils.GetPtr(enabled)
	return p
}

func (p *PackageRegistryBuilder) WithPackages(packagetype string, visability string, isRepoPrivate bool) *PackageRegistryBuilder {
	pkg := &models.Package{
		PackageType: utils.GetPtr(packagetype),
		Visibility:  utils.GetPtr(visability),
		Repository:  &models.Repository{IsPrivate: utils.GetPtr(isRepoPrivate)}}

	if p.registry.Packages == nil {
		p.registry.Packages = []*models.Package{pkg}
	} else {
		p.registry.Packages = append(p.registry.Packages, pkg)
	}
	return p
}

func (p *PackageRegistryBuilder) WithNoPackages() *PackageRegistryBuilder {
	p.registry.Packages = nil
	return p
}

func (p *PackageRegistryBuilder) Build() *models.PackageRegistry {
	return p.registry
}
