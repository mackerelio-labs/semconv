package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/types"
	"iter"
	"log"
	"maps"
	"path"
	"slices"

	"golang.org/x/tools/go/packages"

	"github.com/mackerelio-labs/semconv/syntax"
)

const (
	packagePattern      = "go.opentelemetry.io/otel/semconv/v*"
	otherPackagePattern = "go.opentelemetry.io/otel/semconv/v*/*"
)

var (
	debugFlag = flag.Bool("debug", false, "enables debug print")
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("semconv: ")
	flag.Parse()

	for _, pkgPath := range flag.Args() {
		for pkg := range Packages(pkgPath) {
			attrs := make(map[string]map[SymbolName]AttributeName)
			patterns := []string{packagePattern, otherPackagePattern}
			var imp Importer
			pkgs := GroupBy(imp.ImportedPackages(pkg.Imports), patterns)
			for _, sem := range pkgs[packagePattern] {
				attrs[sem.PkgPath] = CollectAttributes(sem)
				if *debugFlag {
					log.Printf("attribute %s %v\n", sem.PkgPath, attrs[sem.PkgPath])
				}
			}
			// We expect two special packages here: httpconv and netconv.
			for _, conv := range pkgs[otherPackagePattern] {
				pi := &PkgInfo{
					Info:  conv.TypesInfo,
					Attrs: attrs,
				}
				refs := ExternalRefs(pi, conv.Syntax)
				attrs[conv.PkgPath] = make(map[SymbolName]AttributeName)
			}
			info := &PkgInfo{
				Info:  pkg.TypesInfo,
				Attrs: attrs,
			}
			refs := ExternalRefs(info, pkg.Syntax)
			if len(refs) > 0 {
				fmt.Println(pkg.PkgPath, slices.Collect(maps.Values(refs)))
			}
		}
	}
}

func Packages(pkgPath string) iter.Seq[*packages.Package] {
	const mode = packages.NeedCompiledGoFiles |
		packages.NeedSyntax |
		packages.NeedTypes |
		packages.NeedTypesInfo |
		packages.LoadAllSyntax
	c := &packages.Config{Mode: mode}
	pkgs, err := packages.Load(c, pkgPath)
	if err != nil {
		log.Fatalf("failed to load package %s: %v\n", pkgPath, err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		log.Fatalln("too many errors")
	}
	return func(yield func(*packages.Package) bool) {
		for _, pkg := range pkgs {
			if !yield(pkg) {
				break
			}
		}
	}
}

type Importer struct {
	cache map[string]struct{}
}

// ImportedPackages returns some packages matched by pattern.
func (imp *Importer) ImportedPackages(imports map[string]*packages.Package) iter.Seq[*packages.Package] {
	if imp.cache == nil {
		imp.cache = make(map[string]struct{})
	}
	return func(yield func(*packages.Package) bool) {
		for _, pkg := range imports {
			_, ok := imp.cache[pkg.PkgPath]
			if !ok {
				for p := range imp.ImportedPackages(pkg.Imports) {
					if !yield(p) {
						return
					}
				}
				imp.cache[pkg.PkgPath] = struct{}{}
			}
			if !yield(pkg) {
				return
			}
		}
	}
}

// GroupBy classifies pkgs into appropriate patterns by package path.
// If there are duplicated packages, they don't keep in result except the first one.
//
// Pattern is exactly same as [path.Match].
func GroupBy(pkgs iter.Seq[*packages.Package], patterns []string) map[string][]*packages.Package {
	m := make(map[string][]*packages.Package)
	for pkg := range Uniq(pkgs) {
		for _, pattern := range patterns {
			ok, err := path.Match(pattern, pkg.PkgPath)
			if err != nil {
				log.Fatalf("failed to match %s: %v\n", pkg.PkgPath, err)
			}
			if ok {
				m[pattern] = append(m[pattern], pkg)
				break
			}
		}
	}
	return m
}

// Name represents the name of the constants, variables or functions in the semconv package.
//
// For example: CloudRegionKey, CloudProviderAWS.
type SymbolName string

// AttributeName represents the attribute name of the OpenTelemetry Semantic Conventions.
//
// For example: service.instance.id.
type AttributeName string

// CollectAttributes collects name-and-attributes pairs provided in the top-level scope of the semconv package.
func CollectAttributes(pkg *packages.Package) map[SymbolName]AttributeName {
	attrs := make(map[SymbolName]AttributeName)
	scope := pkg.Types.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		switch p := obj.(type) {
		case *types.Const:
			// ex: const ServiceInstanceIDKey = attribute.Key("service.instance.id")
			attrs[SymbolName(name)] = AttributeName(p.Val().String())
		case *types.Var:
			// ex: var SystemMemoryStateUsed = SystemMemoryStateUsedKey.String("used")
			named := extractAttribute(pkg, p)
			if named == nil {
				log.Printf("failed to get a key corresponding to %s in %s\n", p.Name(), pkg.PkgPath)
				continue
			}
			attrs[named.Name] = named.Key
		case *types.Func:
			// ex: func ServiceInstanceID(string) attribute.KeyValue
			// HACK
			keyName := name + "Key"
			key := scope.Lookup(keyName)
			v, ok := key.(*types.Const)
			if !ok {
				log.Printf("key %s is not exist in %s\n", keyName, pkg.PkgPath)
				continue
			}
			attrs[SymbolName(name)] = AttributeName(v.Val().String())
		}
	}
	return attrs
}

// extractAttribute returns a symbol- and attribute-name pair from the declaration of v.
func extractAttribute(pkg *packages.Package, v *types.Var) *NamedAttribute {
	parse := func(n *ast.ValueSpec) (*NamedAttribute, bool) {
		p := parseNamedAttribute(pkg, n)
		return p, p != nil
	}
	for _, f := range pkg.Syntax {
		if named, ok := syntax.Lookup(f, parse); ok {
			return named
		}
	}
	return nil
}

type NamedAttribute struct {
	Name SymbolName
	Key  AttributeName
}

// parseNamedAttribute returns a symbol name and an attribute name corresponding to that.
// It expects expr is described as follows:
//
//	var SystemMemoryStateUsed = SystemMemoryStateUsedKey.String("used")
func parseNamedAttribute(pkg *packages.Package, expr *ast.ValueSpec) *NamedAttribute {
	if len(expr.Names) != 1 {
		return nil
	}
	name := expr.Names[0]

	if len(expr.Values) != 1 {
		return nil
	}
	call, ok := expr.Values[0].(*ast.CallExpr)
	if !ok {
		return nil
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	key, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil
	}
	keyObj, ok := pkg.TypesInfo.Uses[key]
	if !ok {
		return nil
	}
	c, ok := keyObj.(*types.Const)
	if !ok {
		return nil
	}
	return &NamedAttribute{
		Name: SymbolName(name.Name),
		Key:  AttributeName(c.Val().String()),
	}
}

func ExternalRefs(info *PkgInfo, files []*ast.File) map[SymbolName][]AttributeName {
	refs := make(map[SymbolName][]AttributeName)
	for _, f := range files {
		for named := range syntax.Search(f, info.MatchAttribute) {
			refs[named.Name] = append(refs[named.Name], named.Key)
		}
	}
	return refs
}

type PkgInfo struct {
	Info  *types.Info
	Attrs map[string]map[SymbolName]AttributeName
}

func (info *PkgInfo) MatchAttribute(expr *ast.SelectorExpr) (*NamedAttribute, bool) {
	p, ok := expr.X.(*ast.Ident)
	if !ok {
		return nil, false
	}

	pkg, ok := info.Info.Uses[p].(*types.PkgName)
	if !ok {
		return nil, false
	}
	pkgPath := pkg.Pkg().Path()
	m, ok := info.Attrs[pkgPath]
	if !ok {
		return nil, false
	}

	name := SymbolName(expr.Sel.Name)
	key, ok := m[name]
	if !ok {
		log.Printf("%s.%s is not exist\n", pkgPath, name)
	}
	return &NamedAttribute{
		Name: SymbolName(name),
		Key:  key,
	}, true
}
