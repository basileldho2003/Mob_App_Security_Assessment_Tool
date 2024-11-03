rule Vulnerable_Libraries
{
    strings:
        $old_okhttp = /okhttp\-2\.\d\.\d/
        $old_glide = /glide\-3\.\d\.\d/
        $old_retrofit = /retrofit\-1\.\d\.\d/
    condition:
        any of them
}
