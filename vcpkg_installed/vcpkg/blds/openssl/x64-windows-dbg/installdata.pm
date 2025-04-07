package OpenSSL::safe::installdata;

use strict;
use warnings;
use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw(
    @PREFIX
    @libdir
    @BINDIR @BINDIR_REL_PREFIX
    @LIBDIR @LIBDIR_REL_PREFIX
    @INCLUDEDIR @INCLUDEDIR_REL_PREFIX
    @APPLINKDIR @APPLINKDIR_REL_PREFIX
    @ENGINESDIR @ENGINESDIR_REL_LIBDIR
    @MODULESDIR @MODULESDIR_REL_LIBDIR
    @PKGCONFIGDIR @PKGCONFIGDIR_REL_LIBDIR
    @CMAKECONFIGDIR @CMAKECONFIGDIR_REL_LIBDIR
    $VERSION @LDLIBS
);

our @PREFIX                     = ( 'C:\Users\aaaa\source\repos\OPGRABBERS\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug' );
our @libdir                     = ( 'C:\Users\aaaa\source\repos\OPGRABBERS\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\lib' );
our @BINDIR                     = ( 'C:\Users\aaaa\source\repos\OPGRABBERS\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\bin' );
our @BINDIR_REL_PREFIX          = ( 'bin' );
our @LIBDIR                     = ( 'C:\Users\aaaa\source\repos\OPGRABBERS\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\lib' );
our @LIBDIR_REL_PREFIX          = ( 'lib' );
our @INCLUDEDIR                 = ( 'C:\Users\aaaa\source\repos\OPGRABBERS\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\include' );
our @INCLUDEDIR_REL_PREFIX      = ( 'include' );
our @APPLINKDIR                 = ( 'C:\Users\aaaa\source\repos\OPGRABBERS\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\include\openssl' );
our @APPLINKDIR_REL_PREFIX      = ( 'include/openssl' );
our @ENGINESDIR                 = ( 'C:\Users\aaaa\source\repos\OPGRABBERS\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\lib\engines-3' );
our @ENGINESDIR_REL_LIBDIR      = ( 'engines-3' );
our @MODULESDIR                 = ( 'C:\Users\aaaa\source\repos\OPGRABBERS\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\bin' );
our @MODULESDIR_REL_LIBDIR      = ( '..\bin' );
our @PKGCONFIGDIR               = ( 'C:\Users\aaaa\source\repos\OPGRABBERS\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\lib' );
our @PKGCONFIGDIR_REL_LIBDIR    = ( '' );
our @CMAKECONFIGDIR             = ( 'C:\Users\aaaa\source\repos\OPGRABBERS\vcpkg_installed\vcpkg\pkgs\openssl_x64-windows\debug\share\openssl' );
our @CMAKECONFIGDIR_REL_LIBDIR  = ( '..\share\openssl' );
our $VERSION                    = '3.4.1';
our @LDLIBS                     =
    # Unix and Windows use space separation, VMS uses comma separation
    $^O eq 'VMS'
    ? split(/ *, */, 'ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib ')
    : split(/ +/, 'ws2_32.lib gdi32.lib advapi32.lib crypt32.lib user32.lib ');

1;
