import struct
import pefile
from enum import Enum
from pathlib import Path
from typing import Dict, Any, Optional
from .exceptions import DLLLoadError

class DLLType(Enum):
    DOTNET = "dotnet"
    NATIVE = "native"
    MIXED = "mixed"  # C++/CLI
    COM = "com"
    UNKNOWN = "unknown"

class Architecture(Enum):
    X86 = "x86"
    X64 = "x64"
    ANYCPU = "anycpu"
    ARM = "arm"
    UNKNOWN = "unknown"

class DLLAnalyzer:
    """
    Analyzes DLL files to determine their type, architecture, and characteristics.
    """
    
    # PE constants
    IMAGE_FILE_MACHINE_I386 = 0x014c
    IMAGE_FILE_MACHINE_AMD64 = 0x8664
    IMAGE_FILE_MACHINE_ARM = 0x01c0
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64
    
    def __init__(self, dll_path: str):
        self.dll_path = Path(dll_path)
        self.pe = None
        self._parse_pe()
    
    def _parse_pe(self):
        """Parse the PE file."""
        if not self.dll_path.exists():
            raise DLLLoadError(f"DLL not found: {self.dll_path}")
        
        try:
            self.pe = pefile.PE(str(self.dll_path))
        except Exception as e:
            raise DLLLoadError(f"Failed to parse PE file: {e}")
    
    def get_dll_type(self) -> DLLType:
        """
        Determine if DLL is .NET, Native, Mixed, or COM.
        
        Returns:
            DLLType enum value
        """
        has_clr = self._has_clr_header()
        has_com = self._has_com_descriptor()
        exports = self._get_exports()
        
        # Check for .NET
        if has_clr:
            # Check if mixed mode (has native exports too)
            if exports and len(exports) > 0:
                return DLLType.MIXED
            return DLLType.DOTNET
        
        # Check for COM (has type library or COM exports)
        if has_com or self._has_typelib():
            return DLLType.COM
        
        # Native if it has exports but no CLR
        if exports:
            return DLLType.NATIVE
            
        return DLLType.UNKNOWN
    
    def get_architecture(self) -> Architecture:
        """Determine DLL architecture from PE header."""
        machine = self.pe.FILE_HEADER.Machine
        
        if machine == self.IMAGE_FILE_MACHINE_I386:
            # Check for 32-bit .NET AnyCPU (can run on x64)
            if self._has_clr_header() and self.pe.OPTIONAL_HEADER.Magic == 0x10b:
                # Check COR20 header for AnyCPU flag
                return self._check_dotnet_arch()
            return Architecture.X86
        elif machine == self.IMAGE_FILE_MACHINE_AMD64:
            return Architecture.X64
        elif machine in (self.IMAGE_FILE_MACHINE_ARM, self.IMAGE_FILE_MACHINE_ARM64):
            return Architecture.ARM
        
        return Architecture.UNKNOWN
    
    def _check_dotnet_arch(self) -> Architecture:
        """Check .NET specific architecture flags."""
        try:
            clr_header = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            if clr_header.VirtualAddress:
                cor20 = self.pe.get_offset_from_rva(clr_header.VirtualAddress)
                # Flags at offset 16 in COR20 header
                flags = struct.unpack_from("<I", self.pe.__data__, cor20 + 16)[0]
                # 0x2 = 32BITREQUIRED, 0x200 = 32BITPREFERRED
                if flags & 0x2:
                    return Architecture.X86
                return Architecture.ANYCPU
        except:
            pass
        return Architecture.X86
    
    def _has_clr_header(self) -> bool:
        """Check if PE has CLR header (indicates .NET)."""
        try:
            clr_header = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]  # IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
            return clr_header.VirtualAddress != 0 and clr_header.Size != 0
        except:
            return False
    
    def _has_com_descriptor(self) -> bool:
        """Check for COM registration entries."""
        # Check for DllRegisterServer export
        exports = self._get_exports()
        com_methods = {'DllRegisterServer', 'DllUnregisterServer', 'DllGetClassObject'}
        return bool(com_methods.intersection(set(exports)))
    
    def _has_typelib(self) -> bool:
        """Check if DLL contains a type library resource."""
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.id == 2:  # RT_RCDATA or TypeLib
                        return True
        except:
            pass
        return False
    
    def _get_exports(self) -> list:
        """Get list of exported function names."""
        exports = []
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        exports.append(exp.name.decode('utf-8', errors='ignore'))
        except:
            pass
        return exports
    
    def get_metadata(self) -> Dict[str, Any]:
        """
        Get comprehensive metadata about the DLL.
        
        Returns:
            Dictionary with DLL metadata
        """
        dll_type = self.get_dll_type()
        arch = self.get_architecture()
        
        metadata = {
            "path": str(self.dll_path.absolute()),
            "name": self.dll_path.name,
            "type": dll_type.value,
            "architecture": arch.value,
            "is_dotnet": dll_type in (DLLType.DOTNET, DLLType.MIXED),
            "is_mixed": dll_type == DLLType.MIXED,
            "is_com": dll_type == DLLType.COM,
            "has_exports": len(self._get_exports()) > 0,
            "exports": self._get_exports()[:20],  # Limit to first 20
            "file_size": self.dll_path.stat().st_size,
            "pe_timestamp": self.pe.FILE_HEADER.TimeDateStamp,
        }
        
        # Try to get .NET version if applicable
        if metadata["is_dotnet"]:
            metadata["dotnet_version"] = self._get_framework_version()
        
        return metadata
    
    def _get_framework_version(self) -> Optional[str]:
        """Extract .NET framework version from metadata."""
        try:
            # Look for version string in .NET metadata
            clr_header = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
            if clr_header.VirtualAddress:
                # Metadata root is typically at RVA + 8
                metadata_rva = struct.unpack_from("<I", self.pe.__data__, 
                    self.pe.get_offset_from_rva(clr_header.VirtualAddress) + 8)[0]
                metadata_offset = self.pe.get_offset_from_rva(metadata_rva)
                
                # Read version string length and value
                version_len = struct.unpack_from("<I", self.pe.__data__, metadata_offset + 12)[0]
                version_str = self.pe.__data__[metadata_offset + 16:metadata_offset + 16 + version_len]
                return version_str.decode('utf-8', errors='ignore').strip('\x00')
        except:
            pass
        return None
    
    def check_compatibility(self) -> bool:
        """
        Check if DLL architecture is compatible with current Python process.
        
        Returns:
            True if compatible, raises ArchitectureMismatchError otherwise
        """
        import sys
        dll_arch = self.get_architecture()
        
        # Check Python architecture
        is_64bit = sys.maxsize > 2**32
        
        if dll_arch == Architecture.X64 and not is_64bit:
            raise ArchitectureMismatchError(
                f"DLL is x64 but Python is 32-bit. Use 64-bit Python."
            )
        elif dll_arch == Architecture.X86 and is_64bit:
            # x86 DLL can run on x64 Python via WOW64, but .NET might have issues
            if self.get_dll_type() == DLLType.DOTNET:
                raise ArchitectureMismatchError(
                    f"DLL is x86 .NET but Python is 64-bit. Architecture mismatch."
                )
        
        return True
