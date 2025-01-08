-- my_custom_script.nse

local nmap = require "nmap"
local shortport = require "shortport"

-- Define the script description
description = [[
This script checks if port 8080 is open on the target host.
]]

author = "YourName"

-- Define the script action
portrule = shortport.port_or_service(8080, "http")

action = function(host, port)
    return "Port 8080 is open!"
end
