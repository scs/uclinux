
Version 1.38.0

New Libraries

     * Flyweight:
          + Design pattern to manage large quantities of highly redundant objects, from Joaquín M López Muñoz.
     * ScopeExit:
          + Execute arbitrary code at scope exit, from Alexander Nasonov.
     * Swap:
          + Enhanced generic swap function, from Joseph Gauterin.

Updated Libraries

     * Any:
          + Use a by-value argument for operator= (#2311).
     * Accumulators:
          + Add rolling_sum, rolling_count and rolling_mean accumulators.
     * Config:
          + Add new macros BOOST_NO_STD_UNORDERED and BOOST_NO_INITIALIZER_LISTS.
          + Added Codegear compiler support.
          + Added Dragonfly to the BSD family of configs.
          + Updated MSVC's binary ABI settings to match compiler default when doing 64-bit builds.
          + Recognise latest compilers from MS and Intel.
     * Date_Time:
          + Added support for formatting and reading time durations longer than 24 hours with new formatter: %0.
          + Removed the testfrmwk.hpp file from the public include directory.
          + Fixed several bugs and compile errors.
          + For full details see the change history
     * Exception:
          + Improved and more customizable diagnostic_information output.
     * Filesystem:
          + Fix native(name) test failures on POSIX-like systems.
          + Several bugfixes (#2543, #2224, #2531, #1840, #2542).
     * Graph:
          + Added a new algorithms for Traveling Salesman Problem approximation (metric_tsp_approx) and resource-constrained Shortest Paths (r_c_shortest_paths).
          + Support for named vertices in adjacency_list.
          + A number of bugfixes ( #416, #1622, #1700, #2209, #2392, #2460, and #2550)
     * Hash:
          + boost/functional/detail/container_fwd.hpp has been moved to boost/detail/container_fwd.hpp. The current location is deprecated.
          + For more detail, see the library changelog.
     * Interprocess:
          + Updated documentation to show rvalue-references funcions instead of emulation functions.
          + More non-copyable classes are now movable.
          + Move-constructor and assignments now leave moved object in default-constructed state instead of just swapping contents.
          + Several bugfixes (#2391, #2431, #1390, #2570, #2528).
     * Intrusive:
          + New treap-based containers: treap, treap_set, treap_multiset.
          + Corrected compilation bug for Windows-based 64 bit compilers.
          + Corrected exception-safety bugs in container constructors.
          + Updated documentation to show rvalue-references funcions instead of emulation functions.
     * Lexical Cast:
          + Changed to work without RTTI when BOOST_NO_TYPEID is defined. (#1220).
     * Math:
          + Added Johan Råde's optimised floating point classification routines.
          + Fixed code so that it compiles in GCC's -pedantic mode (bug report #1451).
     * Multi-index Containers: Some redundant type definitions have been deprecated. Consult the library release notes for further information.
     * Proto:
          + Fix problem with SFINAE of binary operators (Bug 2407).
          + Fix proto::call transform for callable transforms with >3 arguments.
          + result_of::value changed behavior for array-by-value terminals.
          + unpack_expr requires only Forward Sequences rather than Random Access Sequences.
          + Deprecate legacy undocumented BOOST_PROTO_DEFINE_(VARARG_)FUNCTION_TEMPLATE macros.
          + Add BOOST_PROTO_REPEAT and BOOST_PROTO_LOCAL_ITERATE macros to help with repetitive code generation
          + Support for nullary expressions with tag types other than proto::tag::terminal
          + Allow 0- and 1-argument variants of proto::or_ and proto::and_
     * Regex:
          + Breaking change: empty expressions, and empty alternatives are now allowed when using the Perl regular expression syntax. This change has been added for Perl compatibility, when the new syntax_option_type no_empty_expressions is set then the old behaviour is preserved and empty expressions are prohibited. This is issue #1081.
          + Added support for Perl style ${n} expressions in format strings (issue #2556).
          + Added support for accessing the location of sub-expressions within the regular expression string (issue #2269).
          + Fixed compiler compatibility issues #2244, #2514, and #2458.
     * Thread:
          + No longer catches unhandled exceptions in threads as this debuggers couldn't identify the cause of unhandled exceptions in threads. An unhandled exception will still cause the application to terminate.
     * TR1:
          + Added support for the TR1 math functions and the unordered containers.
     * Type Traits:
          + Added support for Codegear intrinsics.
          + Minor tweaks to warning suppression and alignment_of code.
     * Unordered:
          + Use boost::swap.
          + Use a larger prime number list for selecting the number of buckets.
          + Use aligned storage to store the types.
          + Add support for C++0x initializer lists where they're available.
          + For more detail, see the library changelog.
     * Xpressive:
          + basic_regex gets nested syntax_option_flags and value_type typedef, for compatibility with std::basic_regex
          + Ported to Proto v4; Proto v2 at boost/xpressive/proto has been removed.
          + regex_error inherits from boost::exception

Other Changes

     * Experimental support for building Boost with CMake has been introduced in this version. For more details see the wiki, Discussion is taking place on the Boost-cmake mailing list.
     * Fixed subversion properties for several files. Most notably, unix shell scripts should alway have unix line endings, even in the windows packages.

Compilers Tested

   Boost's primary test compilers are:
     * OS X:
          + GCC 4.0.1 on Intel OS X 10.4.10, 10.5.2
          + GCC 4.0.1 on PowerPC OS X 10.4.9
     * Linux:
          + GCC 4.3.2 on Ubuntu Linux.
          + GCC 4.3.3 on Debian "unstable".
     * HP-UX:
          + GCC 4.2.1 on HP-UX 64-bit.
          + HP C/aC++ B3910B A.06.17 on HP-UX 64-bit.
     * Windows:
          + Visual C++ 7.1 SP1, 8.0 SP1 and 9.0 SP1 on Windows XP.

   Boost's additional test compilers include:
     * Linux:
          + GCC 4.1.1, 4.2.1 on 64-bit Red Hat Enterprise Linux
          + GCC 4.1.2 on 64-bit Redhat Server 5.1
          + GCC 3.4.3, GCC 4.0.1, GCC 4.2.4 and GCC 4.3.2 on Red Hat Enterprise Linux
          + GCC 4.3.2 with C++0x extensions
          + GCC 4.2.1 on OpenSuSE Linux
          + pgCC 8.0-0a 64-bit target on Red Hat Enterprise Linux
          + QLogic PathScale(TM) Compiler Suite: Version 3.1 on Red Hat Enterprise Linux
     * OS X:
          + Intel 9.1, 10.0 on OS X 10.4.10
          + Intel 10.1, 11.0 on OS X 10.5.2
     * Windows:
          + Visual C++ 9.0 on Vista EE 64-bit.
          + Visual C++ 9.0 express on Vista 32-bit.
          + Visual C++ 9.0 on XP 32-bit.
          + Visual C++ 8.0, using STLport, on XP and Windows Mobile 5.0
          + Visual C++ 7.1, using STLport, on XP
          + Borland 5.9.3
          + Borland 6.1.0
          + Intel C++ 11.0, with a Visual C++ 9.0 backend, on XP 32-bit.
          + Intel C++ 11.0, with a Visual C++ 9.0 backend, on Vista 64-bit.
          + Comeau 4.3.10.1 beta 2, with a Visual C++ 9.0 backend.
          + GCC 3.4.4, on Cygwin
     * AIX:
          + IBM XL C/C++ Enterprise Edition for AIX, V10.1.0.0, on AIX Version 5.3.0.40
     * FreeBSD:
          + GCC 4.2.1 on FreeBSD 7.
     * NetBSD:
          + GCC 4.1.2 on NetBSD 4.0/i386 and NetBSD 4.0/amd64.
     * QNX:
          + QNX Software Development Platform 6.4.0 x86
     * Solaris:
          + Sun C++ 5.7, 5.8, 5.9 on Solaris 5.10
          + GCC 3.4.6 on Solaris 5.10

Acknowledgements

   Beman Dawes, Eric Niebler, Rene Rivera, and Daniel James managed this release. Thanks to Vicente Botet for helping compile these release notes.
