
import python
import semmle.python.pointsto.PointsTo
import semmle.python.pointsto.PointsToContext

from ControlFlowNode f, Location l, Context c

where not PointsTo::Test::reachableBlock(f.getBasicBlock(), c) and c.isImport() and
(f.getNode() instanceof FunctionExpr or f.getNode() instanceof ClassExpr) and
l = f.getLocation() and l.getFile().getName().matches("%test.py")
select l.getStartLine()