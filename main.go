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
			attrs := make(map[string]map[Name]AttributeKey)
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

const mode = packages.NeedCompiledGoFiles |
	packages.NeedSyntax |
	packages.NeedTypes |
	packages.NeedTypesInfo |
	packages.LoadAllSyntax

func Packages(pkgPath string) iter.Seq[*packages.Package] {
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

// Name represents the name of the OpenTelemetry semantic conventions.
type Name string

type AttributeKey string

func CollectAttributes(pkg *packages.Package) map[Name]AttributeKey {
	attrs := make(map[Name]AttributeKey)
	scope := pkg.Types.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		switch p := obj.(type) {
		case *types.Const:
			attrs[Name(name)] = AttributeKey(p.Val().String())
		case *types.Var:
			named := lookupVar(pkg, p)
			if named == nil {
				log.Printf("failed to get a key corresponding to %s in %s\n", p.Name(), pkg.PkgPath)
				continue
			}
			attrs[named.Name] = named.Key
		case *types.Func:
			// HACK
			keyName := name + "Key"
			key := scope.Lookup(keyName)
			v, ok := key.(*types.Const)
			if !ok {
				log.Printf("key %s is not exist in %s\n", keyName, pkg.PkgPath)
				continue
			}
			attrs[Name(name)] = AttributeKey(v.Val().String())
		}
	}
	return attrs
}

func lookupVar(pkg *packages.Package, v *types.Var) *NamedAttribute {
	for _, f := range pkg.Syntax {
		for n := range ast.Preorder(f) {
			x, ok := n.(*ast.ValueSpec)
			if !ok {
				continue
			}
			if named := lookupNamedAttribute(pkg, x); named != nil {
				return named
			}
		}
	}
	return nil
}

type NamedAttribute struct {
	Name Name
	Key  AttributeKey
}

func lookupNamedAttribute(pkg *packages.Package, expr *ast.ValueSpec) *NamedAttribute {
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
		Name: Name(name.Name),
		Key:  AttributeKey(c.Val().String()),
	}
}

func ExternalRefs(info *PkgInfo, files []*ast.File) map[Name]AttributeKey {
	refs := make(map[Name]AttributeKey)
	for _, f := range files {
		for name, key := range externalVarsInFile(info, f) {
			refs[name] = key
		}
	}
	return refs
}

func externalVarsInFile(info *PkgInfo, f *ast.File) iter.Seq2[Name, AttributeKey] {
	return func(yield func(Name, AttributeKey) bool) {
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
	Attrs map[string]map[Name]AttributeKey
}

func (info *PkgInfo) MatchAttribute(expr *ast.SelectorExpr) (Name, AttributeKey, bool) {
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

	name := Name(expr.Sel.Name)
	return name, m[name], true
}
