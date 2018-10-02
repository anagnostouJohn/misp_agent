rule zbot0
{
      meta:
		author="malware-lu"
     strings:
        $a = "__SYSTEM__" wide
        $b = "*tanentry*"
        $c = "*<option"
        $d = "*<select"
        $e = "*<input"

     condition:
        ($a and $b) or ($c and $d and $e)
}


rule zbot16
{
      meta:
		author="malware-lu"
     strings:
        $a = "__SYSTEM__" wide
        $b = "*tanentry*"
        $c = "*<option"
        $d = "*<select"
        $e = "*<input"

     condition:
        ($a and $b) or ($c and $d and $e)
}

rule zbot31
{
      meta:
		author="malware-lu"
     strings:
        $a = "__SYSTEM__" wide
        $b = "*tanentry*"
        $c = "*<option"
        $d = "*<select"
        $e = "*<input"

     condition:
        ($a and $b) or ($c and $d and $e)
}

rule zbot462
{
      meta:
		author="malware-lu"
     strings:
        $a = "__SYSTEM__" wide
        $b = "*tanentry*"
        $c = "*<option"
        $d = "*<select"
        $e = "*<input"

     condition:
        ($a and $b) or ($c and $d and $e)
}

rule test61
{
      meta:
		author="malware-lu"
     strings:
        $a = "__SYSTEM__" wide
        $b = "*tanentry*"
        $c = "*<option"
        $d = "*<select"
        $e = "*<input"

     condition:
        ($a and $b) or ($c and $d and $e)
}

rule test76
{
      meta:
		author="malware-lu"
     strings:
        $a = "__SYSTEM__" wide
        $b = "*tanentry*"
        $c = "*<option"
        $d = "*<select"
        $e = "*<input"

     condition:
        ($a and $b) or ($c and $d and $e)
}

rule test91
{
      meta:
		author="malware-lu"
     strings:
        $a = "__SYSTEM__" wide
        $b = "*tanentry*"
        $c = "*<option"
        $d = "*<select"
        $e = "*<input"

     condition:
        ($a and $b) or ($c and $d and $e)
}
