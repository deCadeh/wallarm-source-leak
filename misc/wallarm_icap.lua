--

local fiber = require('fiber')

local M = {}

M.channel = fiber.channel(100)
M.processed = 0
M.dropped = 0


function M.get()
  local id = M.channel:get()

  if id ~= nil then
    local tuple = box.space.requests:get{id}
    if tuple then
      return tuple[2]
    end
  end
end



local function has_long_values( entry)
  if entry == nil then return false end

  -- compare cdata:NULL with nil
  if entry[2][1] ~= nil then
    if #entry[2][1] > 100 then return true end
  end

  -- hash value type
  if entry[2][8][3] then
    for _,e in pairs(entry[2][8][3]) do
      if has_long_values( e) then return true end
    end
  end

  -- array value type
  if entry[2][8][4] then
    for _,e in pairs(entry[2][8][4]) do
      if has_long_values( e) then return true end
    end
  end

  return false
end

wallarm.register_request_handler( function(req, tuple)
  local post = req:post()
  local upload = false

  -- multiparts
  if not post then return end
  if not post[2][8][1] then return end

  for _,e in pairs(post[2][8][1]) do
    if has_long_values(e) then
      upload = true
      break
    end
  end

  if not upload then
    return
  end

  if M.channel:put( tuple[1]) then
    M.processed = M.processed + 1
  else
    M.dropped = M.dropped + 1
  end
end)


return M
