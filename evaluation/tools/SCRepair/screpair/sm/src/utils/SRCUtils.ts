/**
 * @author: Xiao Liang Yu <xiaoly@comp.nus.edu.sg>
 * 
 */


import prettier, { AST as prettier_AST } from 'prettier';
import prettier_plugin_solidity from 'prettier-plugin-solidity';
import { ASTNode } from 'solidity-parser-antlr';
import util from 'util';
import { DeepReadonly } from 'ts-essentials';

export function a2S(ast: DeepReadonly<ASTNode>): string {
  try {
    const src: string = (prettier.format as any)('PLACEHOLDER', {
      plugins: [
        prettier_plugin_solidity,
        {
          parsers: {
            custom: {
              ...prettier_plugin_solidity.parsers['solidity-parse'],
              parse: () => ast as prettier_AST,
            },
          },
        },
      ],
      parser: 'custom',
    });

    return src;
  } catch (e) {
    console.error(`AST = \n${util.inspect(ast as any, true, Infinity, true)}`);
    console.error(e.stack);
    throw new Error(e);
  }
}
