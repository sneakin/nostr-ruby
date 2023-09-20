class Object
  def try m, *a, **o, &cb
    send(m, *a, **o, &cb)
  end
end

class NilClass
  def try m, *a, **o, &cb
    nil
  end
end
