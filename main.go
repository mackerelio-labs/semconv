package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/types"
	"iter"
	"log"
	"maps"
	"slices"
	"strings"

	"golang.org/x/tools/go/packages"

	"github.com/mackerelio-labs/semconv/syntax"
)

const packagePrefix = "go.opentelemetry.io/otel/semconv/"

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
			for _, sem := range ImportedPackages(pkg.Imports, packagePrefix) {
				attrs[sem.Name] = CollectAttributes(sem)
				if *debugFlag {
					log.Printf("attribute %s %v\n", sem.Name, attrs[sem.Name])
				}
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

// ImportedPackages returns some packages matched by pattern.
// If pattern ends with "/", it behaves as a prefix.
func ImportedPackages(imports map[string]*packages.Package, pattern string) iter.Seq2[string, *packages.Package] {
	return func(yield func(string, *packages.Package) bool) {
		for name, pkg := range imports {
			switch {
			case strings.HasSuffix(pattern, "/"):
				if strings.HasPrefix(pkg.PkgPath, pattern) && !yield(name, pkg) {
					return
				}
			default:
				if pkg.PkgPath == pattern && !yield(name, pkg) {
					return
				}
			}
		}
	}
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

func ExternalRefs(info *PkgInfo, files []*ast.File) map[SymbolName]AttributeName {
	refs := make(map[SymbolName]AttributeName)
	for _, f := range files {
		for name, key := range externalVarsInFile(info, f) {
			refs[name] = key
		}
	}
	return refs
}

func externalVarsInFile(info *PkgInfo, f *ast.File) iter.Seq2[SymbolName, AttributeName] {
	return func(yield func(SymbolName, AttributeName) bool) {
		for n := range ast.Preorder(f) {
			x, ok := n.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			name, key, ok := info.MatchAttribute(x)
			if !ok {
				continue
			}
			if !yield(name, key) {
				break
			}
		}
	}
}

type PkgInfo struct {
	Info  *types.Info
	Attrs map[string]map[SymbolName]AttributeName
}

func (info *PkgInfo) MatchAttribute(expr *ast.SelectorExpr) (SymbolName, AttributeName, bool) {
	p, ok := expr.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}

	pkg, ok := info.Info.Uses[p].(*types.PkgName)
	if !ok {
		return "", "", false
	}
	m, ok := info.Attrs[pkg.Name()]
	if !ok {
		return "", "", false
	}

	name := SymbolName(expr.Sel.Name)
	return name, m[name], true
}
