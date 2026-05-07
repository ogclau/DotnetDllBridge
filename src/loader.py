import os
import sys
import clr
from pathlib import Path
from typing import Any, Optional, Dict, Type
from .analyzer import DLLAnalyzer, DLLType, Architecture
from .inspector import DotNetInspector
from .dependency_resolver import DependencyResolver
from .wrapper_generator import WrapperGenerator
from .exceptions import (
    DLLLoadError, NotDotNetAssemblyError, 
    ArchitectureMismatchError, MissingDependencyError
)

class DotNetLoader:
    """
    Intelligent .NET DLL loader with automatic analysis, dependency resolution,
    and wrapper generation.
    """
    
    def __init__(self, auto_resolve_deps: bool = True, generate_wrappers: bool = False):
        """
        Initialize the loader.
        
        Args:
            auto_resolve_deps: Automatically resolve and add dependency paths
            generate_wrappers: Auto-generate Python wrappers on load
        """
        self.auto_resolve_deps = auto_resolve_deps
        self.generate_wrappers = generate_wrappers
        self._loaded_assemblies: Dict[str, Any] = {}
        self._wrappers: Dict[str, str] = {}
    
    def load(self, dll_path: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        """
        Load a .NET DLL with full analysis and optional wrapper generation.
        
        Args:
            dll_path: Path to the DLL file
            namespace: Specific namespace to import (optional)
            
        Returns:
            Dictionary with loaded assembly info and access objects
        """
        dll_path = os.path.abspath(dll_path)
        
        # Step 1: Analyze
        print(f"🔍 Analyzing: {dll_path}")
        analyzer = DLLAnalyzer(dll_path)
        metadata = analyzer.get_metadata()
        
        print(f"   Type: {metadata['type']}")
        print(f"   Architecture: {metadata['architecture']}")
        print(f"   .NET Version: {metadata.get('dotnet_version', 'N/A')}")
        
        # Step 2: Check compatibility
        try:
            analyzer.check_compatibility()
            print("   ✓ Architecture compatible")
        except ArchitectureMismatchError as e:
            print(f"   ✗ {e}")
            raise
        
        # Step 3: Resolve dependencies
        if self.auto_resolve_deps:
            print("   📦 Checking dependencies...")
            resolver = DependencyResolver(dll_path)
            all_ok, missing = resolver.check_all_dependencies()
            
            if not all_ok:
                print(f"   ⚠ Missing dependencies: {[d['name'] for d in missing]}")
                # Add paths of found dependencies to sys.path
                for dep in resolver.get_dependencies():
                    if dep["found"] and dep["path"]:
                        dep_dir = os.path.dirname(dep["path"])
                        if dep_dir not in sys.path:
                            sys.path.append(dep_dir)
                            print(f"   + Added to path: {dep_dir}")
            else:
                print("   ✓ All dependencies resolved")
        
        # Step 4: Load based on type
        dll_type = analyzer.get_dll_type()
        
        if dll_type == DLLType.NATIVE:
            return self._load_native(dll_path, metadata)
        elif dll_type == DLLType.COM:
            return self._load_com(dll_path, metadata)
        elif dll_type in (DLLType.DOTNET, DLLType.MIXED):
            return self._load_dotnet(dll_path, metadata, namespace)
        else:
            raise DLLLoadError(f"Unsupported DLL type: {dll_type.value}")
    
    def _load_dotnet(self, dll_path: str, metadata: Dict, namespace: Optional[str]) -> Dict[str, Any]:
        """Load a .NET assembly."""
        try:
            # Add to CLR references
            clr.AddReference(dll_path)
            
            # Inspect
            inspector = DotNetInspector(dll_path)
            
            # Generate wrapper if requested
            wrapper_path = None
            if self.generate_wrappers:
                wrapper_dir = Path("generated_wrappers")
                wrapper_dir.mkdir(exist_ok=True)
                wrapper_path = wrapper_dir / f"{metadata['name']}_wrapper.py"
                
                generator = WrapperGenerator(dll_path)
                generator.generate_wrapper(str(wrapper_path))
                print(f"   📝 Wrapper generated: {wrapper_path}")
                self._wrappers[metadata['name']] = str(wrapper_path)
            
            # Import namespace if specified
            imported_module = None
            if namespace:
                imported_module = __import__(namespace)
            
            result = {
                "success": True,
                "type": "dotnet",
                "metadata": metadata,
                "inspector": inspector,
                "assembly": inspector.assembly,
                "namespaces": inspector.get_namespaces(),
                "classes": inspector.get_classes(),
                "wrapper_path": wrapper_path,
                "module": imported_module
            }
            
            self._loaded_assemblies[metadata['name']] = result
            return result
            
        except Exception as e:
            raise DLLLoadError(f"Failed to load .NET assembly: {e}")
    
    def _load_native(self, dll_path: str, metadata: Dict) -> Dict[str, Any]:
        """Load a native DLL using ctypes."""
        import ctypes
        
        try:
            # Determine calling convention and load
            dll = ctypes.CDLL(dll_path)
            
            result = {
                "success": True,
                "type": "native",
                "metadata": metadata,
                "handle": dll,
                "exports": metadata.get("exports", [])
            }
            
            print("   ⚠ Native DLL loaded via ctypes. Manual signature definition required.")
            return result
            
        except Exception as e:
            raise DLLLoadError(f"Failed to load native DLL: {e}")
    
    def _load_com(self, dll_path: str, metadata: Dict) -> Dict[str, Any]:
        """Load a COM DLL."""
        try:
            import comtypes.client
            # Would need GUID/CLSID to properly load COM
            # This is a simplified version
            
            result = {
                "success": True,
                "type": "com",
                "metadata": metadata,
                "note": "COM loading requires CLSID. Use comtypes.client.CreateObject('{CLSID}')"
            }
            
            print("   ℹ COM DLL detected. Use comtypes or win32com for full access.")
            return result
            
        except ImportError:
            raise DLLLoadError("comtypes not installed. Install with: pip install comtypes")
    
    def get_class_instance(self, assembly_name: str, class_name: str, *args):
        """
        Get an instance of a .NET class from a loaded assembly.
        
        Args:
            assembly_name: Name of the loaded assembly
            class_name: Full name of the class
            *args: Constructor arguments
            
        Returns:
            Instance of the .NET class
        """
        if assembly_name not in self._loaded_assemblies:
            raise DLLLoadError(f"Assembly {assembly_name} not loaded")
        
        assembly_info = self._loaded_assemblies[assembly_name]
        inspector = assembly_info["inspector"]
        
        # Get type and create instance
        type_obj = inspector.assembly.GetType(class_name)
        if not type_obj:
            raise DLLLoadError(f"Class {class_name} not found")
        
        # Create instance with args
        instance = type_obj(*args)
        return instance
    
    def list_loaded(self) -> List[str]:
        """List all loaded assemblies."""
        return list(self._loaded_assemblies.keys())
