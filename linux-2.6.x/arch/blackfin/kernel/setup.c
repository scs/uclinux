--- setup.c.~1.20.~	2005-04-06 18:59:06.000000000 +0800
+++ setup.c	2005-04-11 14:56:53.850987344 +0800
@@ -96,7 +96,6 @@
 }
 
 static volatile int mem_dma_status = 0;
-irqreturn_t bfin_memdma_int_handler(int irq, void *dev_id, struct pt_regs *regs);
 
 int DmaMemCpy(char *dest_addr , char *source_addr, int size);
 
@@ -425,17 +424,6 @@
 	}
 }
 
-/* MemDma interrupt handler*/
-irqreturn_t bfin_memdma_int_handler(int irq,
-            void *dev_id,
-            struct pt_regs *regs)
-{
-        mem_dma_status = 1 ;
-        *pMDMA_D0_IRQ_STATUS = 0x1;
-        return IRQ_HANDLED;
-}
-
-
 /*copy from SRAM to L1RAM, DMAHandler routine*/
 int DmaMemCpy(char *dest_addr , char *source_addr, int size)
 {
@@ -465,12 +453,13 @@
         *pMDMA_S0_CONFIG = (DMAEN) ;
         asm("ssync;");
 	mem_dma_status = 0;
-        *pMDMA_D0_CONFIG = ( WNR | DI_EN | DMAEN) ;
+        *pMDMA_D0_CONFIG = ( WNR | DMAEN) ;
 
-	/* interrupt handler has not been initialized.
-	   Assume only memdma interrupt will take us
-	   out of idle
-	*/
-	asm("idle;");
-        return 0;
+	//poll DMA Running  bit
+        while((*pMDMA_D0_IRQ_STATUS & 0x8) != 0) {
+	     asm("nop");	     
+	}
+        *pMDMA_D0_IRQ_STATUS = 0x1;
+	return 0;
 }
+
