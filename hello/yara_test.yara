rule zbot20
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


rule zbot
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

rule zbot231
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

rule zbot246
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


rule test62
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

rule tes1
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

rule test92
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

