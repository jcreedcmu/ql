/**
 * @name Arbitrary file write during zip extraction ("Zip Slip")
 * @description Extracting files from a malicious zip archive without validating that the
 *              destination file path is within the destination directory can cause files outside
 *              the destination directory to be overwritten.
 * @kind path-problem
 * @id cs/zipslip
 * @problem.severity error
 * @precision high
 * @tags security
 *       external/cwe/cwe-022
 */

import javascript
import semmle.javascript.security.dataflow.ZipSlip::ZipSlip
import DataFlow::PathGraph

from Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "Unsanitized zip archive $@, which may contain '..', is used in a file system operation.",
  source.getNode(), "item path"



// class Configuration extends TaintTracking::Configuration {
//   Configuration() { this = "TarSlip" }

//   override predicate isSource(DataFlow::Node nd) {
//     isEntrySource(nd)
//   }

//   override predicate isSink(DataFlow::Node sink) {
//     isFuncSink(sink.asExpr())
//   }

//   override predicate isSanitizerGuard(TaintTracking::SanitizerGuardNode nd) {
//      nd instanceof AbsentStringSanitizer
//   }
// }

// /**
//  * A guard that suffices to sanitize a value by establishing that it
//  * does *not* contain a certain bad substring. For example,
//  *
//  *     if (s.indexOf("..") == -1) { ... }
//  *
//  * is considered to sanitize s.
//  */
// class AbsentStringSanitizer extends TaintTracking::SanitizerGuardNode, DataFlow::ValueNode {
//     MethodCallExpr indexOf;
//     override EqualityTest astNode;

//     AbsentStringSanitizer() {
//       indexOf.getMethodName() = "indexOf" and
//         astNode.getAnOperand().getIntValue() = -1 and
//         astNode.getAnOperand() = indexOf
//     }

//     override predicate sanitizes(boolean outcome, Expr e) {
//        outcome = true and
//        e = indexOf.getReceiver()
//     }
// }

// /**
//  * Holds if `nd` is the argument of a tar-archive file-entry event
//  * callback that contains the main bundle of metadata about the file
//  * entry, which includes its file name.
//  */
// predicate isEntrySource(DataFlow::Node nd) {
//   exists(MethodCallExpr mce |
//     mce.getMethodName() = "on"
//     and mce.getArgument(0).(StringLiteral).getStringValue() = "entry"
//     and DataFlow::parameterNode(mce.getArgument(1).(Function).getParameter(0)) = nd
//   )
// }

// /**
//  * Holds if `s` is the name of a method whose first argument is
//  * a filename that may be written to.
//  */
// predicate isFileWritingMethod(string s) {
//    /* FIXME: Perhaps this should be unified with the related (private)
//     predicates in semmle.javascript.frameworks.NodeJSLib */
//    s = "createWriteStream" or
//    s = "writeFile" or
//    s = "writeFileSync"
// }

// /**
//  * Holds if `e` is an expression that is at risk of
//  * being used as a filename which is written to.
//  */
// predicate isFuncSink(Expr e) {
//   exists(MethodCallExpr mce |
//     e = mce.getArgument(0) and
//     isFileWritingMethod(mce.getMethodName())
//   )
// }

// from DataFlow::Node src, DataFlow::Node tgt, Configuration cfg
// where cfg.hasFlow(src, tgt)
// select src, tgt
