import os
import winreg
from pathlib import Path
from typing import List, Set, Optional
import pefile

class DependencyResolver:
    """
    Resolves DLL dependencies by analyzing imports and searching common paths.
    """
    
    def __init__(self, dll_path: str):
        self.dll_path = Path(dll_path).resolve()
        self.search_paths = self._get_search_paths()
    
    def _get_search_paths(self) -> List[Path]:
        """Get list of paths to search for dependencies."""
        paths = [
            self.dll_path.parent,  # Same directory as DLL
            Path.cwd(),            # Current working directory
        ]
        
        # PATH environment
        env_path = os.environ.get('PATH', '')
        paths.extend([Path(p) for p in env_path.split(os.pathsep) if p])
        
        # Windows system directories
        import ctypes
        from ctypes import wintypes
        
        # Get System32 and SysWOW64 paths
        kernel32 = ctypes.windll.kernel32
        buf = ctypes.create_unicode_buffer(260)
        kernel32.GetSystemDirectoryW(buf, 260)
        paths.append(Path(buf.value))
        
        # Add .NET assembly paths
        dotnet_paths = self._get_dotnet_paths()
        paths.extend(dotnet_paths)
        
        return paths
    
    def _get_dotnet_paths(self) -> List[Path]:
        """Get .NET Framework assembly paths."""
        paths = []
        try:
            # Try to find GAC and framework paths
            reg_paths = [
                r"SOFTWARE\Microsoft\.NETFramework\AssemblyFolders",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\AssemblyFoldersEx"
            ]
            
            for reg_path in reg_paths:
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path) as key:
                        for i in range(winreg.QueryInfoKey(key)[0]):
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                path, _ = winreg.QueryValueEx(subkey, None)
                                if path:
                                    paths.append(Path(path))
                except:
                    continue
        except:
            pass
        
        # Common .NET Framework paths
        common_paths = [
            Path(r"C:\Windows\Microsoft.NET\assembly\GAC_MSIL"),
            Path(r"C:\Windows\Microsoft.NET\assembly\GAC_32"),
            Path(r"C:\Windows\Microsoft.NET\assembly\GAC_64"),
        ]
        paths.extend(common_paths)
        
        return paths
    
    def get_dependencies(self) -> List[Dict[str, any]]:
        """
        Analyze DLL and find all dependencies.
        
        Returns:
            List of dependency information dictionaries
        """
        dependencies = []
        
        try:
            pe = pefile.PE(str(self.dll_path))
            
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                return dependencies
            
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                dep_info = {
                    "name": dll_name,
                    "found": False,
                    "path": None,
                    "is_system": False
                }
                
                # Try to find the dependency
                found_path = self._find_dll(dll_name)
                if found_path:
                    dep_info["found"] = True
                    dep_info["path"] = str(found_path)
                    dep_info["is_system"] = self._is_system_dll(found_path)
                
                dependencies.append(dep_info)
                
        except Exception as e:
            print(f"Warning: Could not analyze dependencies: {e}")
        
        return dependencies
    
    def _find_dll(self, dll_name: str) -> Optional[Path]:
        """Search for DLL in known paths."""
        # Try direct paths first
        for path in self.search_paths:
            full_path = path / dll_name
            if full_path.exists():
                return full_path.resolve()
            
            # Try with .dll extension if not present
            if not dll_name.lower().endswith('.dll'):
                full_path = path / f"{dll_name}.dll"
                if full_path.exists():
                    return full_path.resolve()
        
        return None
    
    def _is_system_dll(self, dll_path: Path) -> bool:
        """Check if DLL is a Windows system DLL."""
        system_paths = [
            Path(r"C:\Windows\System32"),
            Path(r"C:\Windows\SysWOW64"),
            Path(r"C:\Windows\System"),
        ]
        return any(str(dll_path).lower().startswith(str(p).lower()) for p in system_paths)
    
    def check_all_dependencies(self) -> tuple:
        """
        Check if all dependencies are available.
        
        Returns:
            Tuple (bool, list_of_missing)
        """
        deps = self.get_dependencies()
        missing = [d for d in deps if not d["found"] and not d["is_system"]]
        return len(missing) == 0, missing
