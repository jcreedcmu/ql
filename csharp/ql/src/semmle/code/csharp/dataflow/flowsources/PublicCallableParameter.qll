/**
 * Provides classes representing data flow sources for parameters of public callables.
 */

import csharp
private import semmle.code.csharp.frameworks.WCF

/**
 * A parameter of a public callable, for example `p` in
 *
 * ```
 * public void M(int p) {
 *   ...
 * }
 * ```
 */
class PublicCallableParameterFlowSource extends DataFlow::ParameterNode {
  PublicCallableParameterFlowSource() {
    exists(Callable c, Parameter p |
      p = this.getParameter() and
      c.(Modifiable).isPublic() and
      c.getAParameter() = p and
      not p.isOut()
    )
  }
}
