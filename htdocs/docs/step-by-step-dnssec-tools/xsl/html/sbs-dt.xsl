<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0">
  <!-- NOTE: This needs to point to the DocBook XSL Stylesheet html/chunk.xsl file -->
  <xsl:import href="/Applications/xxe-std-30/XMLEditor.app/Contents/Resources/addon/config/docbook/xsl/html/chunk.xsl" />
	<xsl:param name="use.id.as.filename" select="1" />
	<xsl:param name="base.dir" select="'html/'" />
	<xsl:param name="chunk.first.sections" select="1" />
</xsl:stylesheet>
