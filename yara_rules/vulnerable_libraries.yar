rule Vulnerable_Libraries
{
    strings:
        $old_okhttp = /okhttp\-2\.[0-9]+\.[0-9]+/
        $old_glide = /glide\-3\.[0-9]+\.[0-9]+/
        $old_retrofit = /retrofit\-1\.[0-9]+\.[0-9]+/
    condition:
        any of them
}
