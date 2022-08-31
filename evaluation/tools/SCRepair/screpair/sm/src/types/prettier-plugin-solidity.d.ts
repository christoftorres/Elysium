declare module 'prettier-plugin-solidity';

declare module 'prettier-plugin-solidity/src/parser' {
  import { ASTNode } from 'solidity-parser-antlr';

  export default function(text: string): ASTNode;
}
