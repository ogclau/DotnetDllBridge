import clr
import System
from System.Reflection import Assembly, BindingFlags
from typing import List, Dict, Any, Optional, Type
import inspect
from .analyzer import DLLAnalyzer, DLLType
from .exceptions import NotDotNetAssemblyError, MethodNotFoundError

class DotNetInspector:
    """
    Inspects .NET assemblies using reflection via pythonnet.
    """
    
    def __init__(self, dll_path: str):
        self.dll_path = dll_path
        self.analyzer = DLLAnalyzer(dll_path)
        
        # Verify it's a .NET assembly
        dll_type = self.analyzer.get_dll_type()
        if dll_type not in (DLLType.DOTNET, DLLType.MIXED):
            raise NotDotNetAssemblyError(
                f"DLL {dll_path} is not a .NET assembly (detected: {dll_type.value})"
            )
        
        self.assembly: Optional[Assembly] = None
        self._load_assembly()
    
    def _load_assembly(self):
        """Load the assembly into the CLR."""
        try:
            # Add reference to the assembly
            clr.AddReference(str(self.dll_path))
            
            # Load the assembly to get full metadata
            self.assembly = Assembly.LoadFrom(str(self.dll_path))
        except Exception as e:
            raise NotDotNetAssemblyError(f"Failed to load assembly: {e}")
    
    def get_types(self) -> List[Type]:
        """Get all public types from the assembly."""
        try:
            return list(self.assembly.GetTypes())
        except Exception as e:
            print(f"Warning: Could not get all types: {e}")
            return []
    
    def get_namespaces(self) -> List[str]:
        """Get all namespaces in the assembly."""
        types = self.get_types()
        namespaces = set()
        for t in types:
            if t.Namespace:
                namespaces.add(t.Namespace)
        return sorted(list(namespaces))
    
    def get_classes(self, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get all classes (reference types, not interfaces/enums).
        
        Args:
            namespace: Filter by namespace (optional)
            
        Returns:
            List of class metadata dictionaries
        """
        types = self.get_types()
        classes = []
        
        for t in types:
            if not t.IsClass or t.IsInterface:
                continue
            
            if namespace and t.Namespace != namespace:
                continue
            
            class_info = {
                "name": t.Name,
                "namespace": t.Namespace,
                "full_name": t.FullName,
                "is_public": t.IsPublic,
                "is_abstract": t.IsAbstract,
                "is_sealed": t.IsSealed,
                "base_type": t.BaseType.Name if t.BaseType else None,
                "interfaces": [i.Name for i in t.GetInterfaces()],
                "methods": self._get_methods_info(t),
                "properties": self._get_properties_info(t),
                "constructors": self._get_constructors_info(t),
                "fields": self._get_fields_info(t),
            }
            classes.append(class_info)
        
        return classes
    
    def _get_methods_info(self, type_obj: Type) -> List[Dict[str, Any]]:
        """Extract method information from a type."""
        methods = []
        
        # Get public instance and static methods
        flags = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly
        
        for method in type_obj.GetMethods(flags):
            if method.IsSpecialName:  # Skip property accessors
                continue
            
            method_info = {
                "name": method.Name,
                "is_static": method.IsStatic,
                "is_virtual": method.IsVirtual,
                "is_abstract": method.IsAbstract,
                "return_type": method.ReturnType.FullName,
                "parameters": [
                    {
                        "name": p.Name,
                        "type": p.ParameterType.FullName,
                        "is_optional": p.IsOptional,
                        "default_value": p.DefaultValue if p.HasDefaultValue else None
                    }
                    for p in method.GetParameters()
                ],
                "attributes": [str(a) for a in method.GetCustomAttributes(True)]
            }
            methods.append(method_info)
        
        return methods
    
    def _get_properties_info(self, type_obj: Type) -> List[Dict[str, Any]]:
        """Extract property information."""
        properties = []
        flags = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static
        
        for prop in type_obj.GetProperties(flags):
            prop_info = {
                "name": prop.Name,
                "type": prop.PropertyType.FullName,
                "can_read": prop.CanRead,
                "can_write": prop.CanWrite,
                "is_static": prop.GetGetMethod() is not None and prop.GetGetMethod().IsStatic
            }
            properties.append(prop_info)
        
        return properties
    
    def _get_constructors_info(self, type_obj: Type) -> List[Dict[str, Any]]:
        """Extract constructor information."""
        constructors = []
        flags = BindingFlags.Public | BindingFlags.Instance
        
        for ctor in type_obj.GetConstructors(flags):
            ctor_info = {
                "parameters": [
                    {
                        "name": p.Name,
                        "type": p.ParameterType.FullName
                    }
                    for p in ctor.GetParameters()
                ]
            }
            constructors.append(ctor_info)
        
        return constructors
    
    def _get_fields_info(self, type_obj: Type) -> List[Dict[str, Any]]:
        """Extract field information."""
        fields = []
        flags = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static
        
        for field in type_obj.GetFields(flags):
            field_info = {
                "name": field.Name,
                "type": field.FieldType.FullName,
                "is_static": field.IsStatic,
                "is_readonly": field.IsInitOnly,
                "is_literal": field.IsLiteral
            }
            fields.append(field_info)
        
        return fields
    
    def get_method_signature(self, class_name: str, method_name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed signature of a specific method.
        
        Args:
            class_name: Full name of the class
            method_name: Name of the method
            
        Returns:
            Method signature dictionary or None
        """
        try:
            type_obj = self.assembly.GetType(class_name)
            if not type_obj:
                return None
            
            # Search for method
            flags = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static
            methods = type_obj.GetMethods(flags)
            
            for method in methods:
                if method.Name == method_name:
                    return {
                        "name": method.Name,
                        "return_type": method.ReturnType.FullName,
                        "parameters": [
                            {
                                "name": p.Name,
                                "type": p.ParameterType.FullName,
                                "position": p.Position,
                                "is_out": p.IsOut,
                                "is_ref": p.ParameterType.IsByRef
                            }
                            for p in method.GetParameters()
                        ],
                        "is_generic": method.IsGenericMethod,
                        "generic_parameters": [p.Name for p in method.GetGenericArguments()] if method.IsGenericMethod else []
                    }
            
            raise MethodNotFoundError(f"Method {method_name} not found in {class_name}")
            
        except MethodNotFoundError:
            raise
        except Exception as e:
            print(f"Error getting method signature: {e}")
            return None
    
    def generate_api_map(self) -> Dict[str, Any]:
        """
        Generate complete API map of the assembly.
        
        Returns:
            Dictionary with complete assembly metadata
        """
        return {
            "assembly_name": self.assembly.GetName().Name,
            "version": str(self.assembly.GetName().Version),
            "location": self.assembly.Location,
            "namespaces": self.get_namespaces(),
            "classes": self.get_classes(),
            "entry_point": self.assembly.EntryPoint.Name if self.assembly.EntryPoint else None,
            "referenced_assemblies": [a.Name for a in self.assembly.GetReferencedAssemblies()]
        }
