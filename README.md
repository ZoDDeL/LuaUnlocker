# LuaUnlocker
Lua Unlocker Source for Live WoW 7.x to 8.x and Classic for use with addons like NerdPack & DarkRotatations.com<br>
Website: https://winifix.github.io/<br>

# Credits
l0l1dk - the logic shared with me, originally written in D-Lang.<br>
Ferib - for assembler logic: https://github.com/WiNiFiX/LuaUnlocker/blob/master/Application/Form1.cs#L46-L58<br>
and https://github.com/WiNiFiX/LuaUnlocker/blob/master/Application/Form1.cs#L74-L85<br>

# How it works
It just resets the "lua-tainted" address to 0 thousands/millions of times per second<br>
so all wow "protected lua" functions end up being called without issues 99% of the time,<br>
they are fooled into believing they not protected functions so run.<br>

# Will it work on Classic wow?
As of now yes, but that may change at anytime

# Screenshot of it working in Classic Beta 
![Screenshot](https://i.imgur.com/GiMAzWy.png)

# Can it be detected?
Yes<br>

# Will it be detected?
Maybe<br>
