<?xml version='1.0'?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    version="1.0">
  <xsl:param name="toc.section.depth" select="2" />
  <xsl:param name="section.autolabel" select="1" />
  <xsl:param name="section.label.includes.component.label" select="1" />
  <xsl:param name="insert.xref.page.number" select="1" />
  <xsl:param name="admon.graphics" select="1" />
  <xsl:param name="admon.graphics.path" select="'../../pictures/'" />
  <xsl:param name="admon.graphics.extension" select="'.png'" />
  <xsl:param name="generate.legalnotice.link" select="1" />

  <xsl:param name="formal.title.placement">
    figure after
    example before
    equation after
    table before
    procedure before
  </xsl:param>

</xsl:stylesheet>
