module Enumerable
  def split_at n
    [ first(n), drop(n) ]
  end
end
