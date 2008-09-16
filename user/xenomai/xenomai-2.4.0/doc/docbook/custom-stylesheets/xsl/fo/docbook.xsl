<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    version="1.0">
  <xsl:import href="http://docbook.sourceforge.net/release/xsl/current/fo/docbook.xsl" />
  <xsl:include href="../common/common.xsl" />
  <xsl:param name="paper.type" select="'A4'"  />
  <xsl:param name="fo.extensions" select="1"  />
  <xsl:param name="page.height.portrait">9in</xsl:param>
  <xsl:param name="page.width.portrait">7in</xsl:param>
  <xsl:param name="page.margin.inner">0.75in</xsl:param>
  <xsl:param name="page.margin.outer">0.50in</xsl:param>
  <xsl:param name="page.margin.top">0.17in</xsl:param>
  <xsl:param name="page.margin.bottom">0.50in</xsl:param>

  <xsl:param name="chunk.section.depth" select="2" />
  <xsl:param name="section.autolabel" select="1" />
  <xsl:param name="section.label.includes.component.label" select="1" />
  <xsl:param name="fop.extensions" select="1" />
  <xsl:param name="insert.xref.page.number" select="1" />
  <xsl:param name="admon.graphics" select="1" />
  <xsl:param name="admon.graphics.extension" select="'.png'" />

  <xsl:attribute-set name="formal.title.properties"
    use-attribute-sets="normal.para.spacing">
    <xsl:attribute name="font-family">Helvetica</xsl:attribute>
    <xsl:attribute name="font-weight">italic</xsl:attribute>
    <xsl:attribute name="font-size">11pt</xsl:attribute>
    <xsl:attribute name="hyphenate">false</xsl:attribute>
    <xsl:attribute name="space-after.minimum">0.4em</xsl:attribute>
    <xsl:attribute name="space-after.optimum">0.6em</xsl:attribute>
    <xsl:attribute name="space-after.maximum">0.8em</xsl:attribute>
  </xsl:attribute-set>
</xsl:stylesheet>

