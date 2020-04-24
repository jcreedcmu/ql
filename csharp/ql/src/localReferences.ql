/**
 * @name Find-references links
 * @description Generates use-definition pairs that provide the data
 *              for find-references in the code viewer.
 * @kind definitions
 * @id csharp/ide-find-references
 * @tags ide-contextual-queries/local-references
 */

import definitions

external string selectedSourceFile();

cached
File getEncodedFile(string name) { result.getAbsolutePath().replaceAll(":", "_") = name }

from Use e, Declaration def, string kind
where def = definitionOf(e, kind) and def.getFile() = getEncodedFile(selectedSourceFile())
select e, def, kind
