rule Debuggable_Application
{
    strings:
        $debuggable = /android:debuggable\s*=\s*["']true["']/
    condition:
        $debuggable
}
