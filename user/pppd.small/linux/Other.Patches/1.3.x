This patch is for earlier 1.3 series kernels. The later 1.3 series kernels
already have this patch.

If you experince an error indicating that the symbols "mod_use_count_" is
not defined then apply this patch.

ELF does not have this problem. Only a.out will complain.

--- v1.3/include/linux/module.h.orig	Thu Oct 19 05:32:32 1995
+++ linux/include/linux/module.h	Thu Oct 19 05:33:44 1995
@@ -90,12 +90,12 @@
  * define the count variable, and usage macros.
  */
 
-extern long mod_use_count_;
 #if defined(CONFIG_MODVERSIONS) && defined(MODULE) && !defined(__GENKSYMS__)
 int Using_Versions; /* gcc will handle this global (used as a flag) correctly */
 #endif
 
 #ifdef MODULE
+extern long mod_use_count_;
 #define MOD_INC_USE_COUNT      mod_use_count_++
 #define MOD_DEC_USE_COUNT      mod_use_count_--
 #define MOD_IN_USE	       (mod_use_count_ != 0)

