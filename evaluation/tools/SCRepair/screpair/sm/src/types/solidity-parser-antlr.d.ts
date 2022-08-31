import { astNodeTypeStrings } from "../lib/utils";

declare module 'solidity-parser-antlr' {
  // Type definitions for solidity-parser-antlr 0.2
  // Project: https://github.com/federicobond/solidity-parser-antlr
  // Definitions by: Leonid Logvinov <https://github.com/LogvinovLeon>
  //                 Alex Browne <https://github.com/albrow>
  //                 Xiao Liang <https://github.com/yxliang01>
  // Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped
  // TypeScript Version: 2.1

  export interface LineColumn {
    line: number;
    column: number;
  }
  export interface CodeRange {
    start: LineColumn;
    end: LineColumn;
  }

  export type FileRootASTNode = ASTNode;

  // Note: This should be consistent with the definition of type ASTNode
  export type ASTNodeTypeString = ASTNode['type'];

  export interface BaseASTNode {
    type: ASTNodeTypeString;
    range?: [number, number];
    loc?: CodeRange;
  }
  export interface SourceUnit extends BaseASTNode {
    type: 'SourceUnit';
    children: ASTNode[]; // TODO: Can be more precise
  } // tslint:disable-line:no-empty-interface
  export interface PragmaDirective extends BaseASTNode {
    type: 'PragmaDirective';
  }
  export interface PragmaName extends BaseASTNode {
    type: 'PragmaName';
  }
  export interface PragmaValue extends BaseASTNode {
    type: 'PragmaValue';
  }
  export interface Version extends BaseASTNode {
    type: 'Version';
  }
  export interface VersionOperator extends BaseASTNode {
    type: 'VersionOperator';
  }
  export interface VersionConstraint extends BaseASTNode {
    type: 'VersionConstraint';
  }
  export interface ImportDeclaration extends BaseASTNode {
    type: 'ImportDeclaration';
  }
  export interface ImportDirective extends BaseASTNode {
    type: 'ImportDirective';
  }
  export interface ContractDefinition extends BaseASTNode {
    type: 'ContractDefinition';
    name: string;
    subNodes: ASTNode[]; // TODO: Can be more precise
  }
  export interface InheritanceSpecifier extends BaseASTNode {
    type: 'InheritanceSpecifier';
  }
  export interface StateVariableDeclaration extends BaseASTNode {
    type: 'StateVariableDeclaration';
    variables: VariableDeclaration[];
  }
  export interface UsingForDeclaration extends BaseASTNode {
    type: 'UsingForDeclaration';
  }
  export interface StructDefinition extends BaseASTNode {
    type: 'StructDefinition';
  }
  export interface ModifierDefinition extends BaseASTNode {
    type: 'ModifierDefinition';
    name: string;
  }
  export interface ModifierInvocation extends BaseASTNode {
    type: 'ModifierInvocation';
    name: string;
  }
  export interface FunctionDefinition extends BaseASTNode {
    type: 'FunctionDefinition';
    name: string;
    parameters: ParameterList;
    body: Block | null;
  }
  export interface ModifierList extends BaseASTNode {
    type: 'ModifierList';
  }
  export interface EventDefinition extends BaseASTNode {
    type: 'EventDefinition';
    name: string;
    parameters: ParameterList;
  }
  export interface EmitStatement extends BaseASTNode {
    type: 'EmitStatement';
  }
  export interface EnumValue extends BaseASTNode {
    type: 'EnumValue';
  }
  export interface EnumDefinition extends BaseASTNode {
    type: 'EnumDefinition';
  }
  export interface ParameterList extends BaseASTNode {
    type: 'ParameterList';
  }
  export interface Parameter extends BaseASTNode {
    type: 'Parameter';
  }
  export interface EventParameterList extends BaseASTNode {
    type: 'EventParameterList';
  }
  export interface EventParameter extends BaseASTNode {
    type: 'EventParameter';
  }
  export interface FunctionTypeParameterList extends BaseASTNode {
    type: 'FunctionTypeParameterList';
  }
  export interface FunctionTypeParameter extends BaseASTNode {
    type: 'FunctionTypeParameter';
  }
  export interface VariableDeclaration extends BaseASTNode {
    type: 'VariableDeclaration';
    isIndexed: boolean;
    isStateVar: boolean;
    typeName: TypeName;
    name: string;
    isDeclaredConst?: boolean;
    storageLocation: string | null;
    expression?: Expression;
    visibility?: 'public' | 'private';
  }
  export interface ArrayTypeName extends BaseASTNode {
    type: 'ArrayTypeName';
  }
  export interface UserDefinedTypeName extends BaseASTNode {
    type: 'UserDefinedTypeName';
  }
  export interface Mapping extends BaseASTNode {
    type: 'Mapping';
    keyType: TypeName;
    valueType: TypeName;
  }
  export interface FunctionTypeName extends BaseASTNode {
    type: 'FunctionTypeName';
  }
  export interface StorageLocation extends BaseASTNode {
    type: 'StorageLocation';
  }
  export interface StateMutability extends BaseASTNode {
    type: 'StateMutability';
  }
  export interface Block extends BaseASTNode {
    type: 'Block';
    statements: Statement[];
  }
  export interface LineComment extends BaseASTNode {
    type: 'LineComment';
  }
  export interface BlockComment extends BaseASTNode {
    type: 'BlockComment';
  }
  export interface ExpressionStatement extends BaseASTNode {
    type: 'ExpressionStatement';
    expression: Expression;
  }
  export interface IfStatement extends BaseASTNode {
    type: 'IfStatement';
    condition: Expression;
    trueBody: Statement;
    falseBody: Statement | null;
  }
  export interface WhileStatement extends BaseASTNode {
    type: 'WhileStatement';
  }
  export interface ForStatement extends BaseASTNode {
    type: 'ForStatement';
  }
  export interface InlineAssemblyStatement extends BaseASTNode {
    type: 'InlineAssemblyStatement';
  }
  export interface DoWhileStatement extends BaseASTNode {
    type: 'DoWhileStatement';
  }
  export interface ContinueStatement extends BaseASTNode {
    type: 'ContinueStatement';
  }
  export interface BreakStatement extends BaseASTNode {
    type: 'BreakStatement';
  }
  export interface ReturnStatement extends BaseASTNode {
    type: 'ReturnStatement';
  }
  export interface ThrowStatement extends BaseASTNode {
    type: 'ThrowStatement';
  }
  export interface VariableDeclarationStatement extends BaseASTNode {
    type: 'VariableDeclarationStatement';
    variables: ASTNode[];
    initialValue?: Expression;
  }
  export interface IdentifierList extends BaseASTNode {
    type: 'IdentifierList';
  }
  export interface ElementaryTypeName extends BaseASTNode {
    type: 'ElementaryTypeName';
    name: string;
  }
  export interface NewExpression extends BaseASTNode {
    type: 'NewExpression';
  }
  export interface ExpressionList extends BaseASTNode {
    type: 'ExpressionList';
  }
  export interface NameValueList extends BaseASTNode {
    type: 'NameValueList';
  }
  export interface NameValue extends BaseASTNode {
    type: 'NameValue';
  }
  export interface FunctionCall extends BaseASTNode {
    type: 'FunctionCall';
    expression: Expression;
    arguments: FunctionCallArguments[];
  }
  export interface FunctionCallArguments extends BaseASTNode {
    type: 'FunctionCallArguments';
  }
  export interface AssemblyBlock extends BaseASTNode {
    type: 'AssemblyBlock';
  }
  export interface AssemblyItem extends BaseASTNode {
    type: 'AssemblyItem';
  }
  export interface AssemblyCall extends BaseASTNode {
    type: 'AssemblyCall';
  }
  export interface AssemblyLocalDefinition extends BaseASTNode {
    type: 'AssemblyLocalDefinition';
  }
  export interface AssemblyAssignment extends BaseASTNode {
    type: 'AssemblyAssignment';
  }
  export interface AssemblyIdentifierOrList extends BaseASTNode {
    type: 'AssemblyIdentifierOrList';
  }
  export interface AssemblyIdentifierList extends BaseASTNode {
    type: 'AssemblyIdentifierList';
  }
  export interface AssemblyStackAssignment extends BaseASTNode {
    type: 'AssemblyStackAssignment';
  }
  export interface LabelDefinition extends BaseASTNode {
    type: 'LabelDefinition';
  }
  export interface AssemblySwitch extends BaseASTNode {
    type: 'AssemblySwitch';
  }
  export interface AssemblyCase extends BaseASTNode {
    type: 'AssemblyCase';
  }
  export interface AssemblyFunctionDefinition extends BaseASTNode {
    type: 'AssemblyFunctionDefinition';
  }
  export interface AssemblyFunctionReturns extends BaseASTNode {
    type: 'AssemblyFunctionReturns';
  }
  export interface AssemblyFor extends BaseASTNode {
    type: 'AssemblyFor';
  }
  export interface AssemblyIf extends BaseASTNode {
    type: 'AssemblyIf';
  }
  export interface AssemblyLiteral extends BaseASTNode {
    type: 'AssemblyLiteral';
  }
  export interface SubAssembly extends BaseASTNode {
    type: 'SubAssembly';
  }
  export interface TupleExpression extends BaseASTNode {
    type: 'TupleExpression';
  }
  export interface ElementaryTypeNameExpression extends BaseASTNode {
    type: 'ElementaryTypeNameExpression';
  }
  export interface NumberLiteral extends BaseASTNode {
    type: 'NumberLiteral';
    number: string;
    subdenomination:
    | null
    | 'wei'
    | 'szabo'
    | 'finney'
    | 'ether'
    | 'seconds'
    | 'minutes'
    | 'hours'
    | 'days'
    | 'weeks'
    | 'years';
  }
  export interface BooleanLiteral extends BaseASTNode {
    type: 'BooleanLiteral';
    value: boolean;
  }
  export interface HexLiteral extends BaseASTNode {
    type: 'HexLiteral';
    value: string;
  }
  export interface StringLiteral extends BaseASTNode {
    type: 'StringLiteral';
    value: string;
  }
  export interface Identifier extends BaseASTNode {
    type: 'Identifier';
    name: string;
  }
  export interface MemberAccess extends BaseASTNode {
    type: 'MemberAccess';
  }
  export type BinOp =
    | '+'
    | '-'
    | '*'
    | '/'
    | '**'
    | '%'
    | '<<'
    | '>>'
    | '&&'
    | '||'
    | '&'
    | '|'
    | '^'
    | '<'
    | '>'
    | '<='
    | '>='
    | '=='
    | '!='
    | '='
    | '|='
    | '^='
    | '&='
    | '<<='
    | '>>='
    | '+='
    | '-='
    | '*='
    | '/='
    | '%=';
  export interface UnaryOperation extends BaseASTNode {
    type: 'UnaryOperation';
  }
  export interface BinaryOperation extends BaseASTNode {
    type: 'BinaryOperation';
    left: Expression;
    right: Expression;
    operator: BinOp;
  }
  export interface Conditional extends BaseASTNode {
    type: 'Conditional';
    trueExpression: ASTNode;
    falseExpression: ASTNode;
  }
  export interface IndexAccess extends BaseASTNode {
    type: 'IndexAccess';
    base: Expression;
    index: Expression;
  }
  export interface MemberAccess extends BaseASTNode {
    type: 'MemberAccess';
    expression: Expression;
    memberName: string;
  }
  export type ASTNode =
    | SourceUnit
    | PragmaDirective
    | PragmaName
    | PragmaValue
    | Version
    | VersionOperator
    | VersionConstraint
    | ImportDeclaration
    | ImportDirective
    | ContractDefinition
    | InheritanceSpecifier
    | StateVariableDeclaration
    | UsingForDeclaration
    | StructDefinition
    | ModifierDefinition
    | ModifierInvocation
    | FunctionDefinition
    | ModifierList
    | EventDefinition
    | EmitStatement
    | EnumValue
    | EnumDefinition
    | ParameterList
    | Parameter
    | EventParameterList
    | EventParameter
    | FunctionTypeParameterList
    | FunctionTypeParameter
    | VariableDeclaration
    | TypeName
    | ArrayTypeName
    | UserDefinedTypeName
    | Mapping
    | FunctionTypeName
    | StorageLocation
    | StateMutability
    | Block
    | LineComment
    | BlockComment
    | ExpressionStatement
    | IfStatement
    | WhileStatement
    | ForStatement
    | InlineAssemblyStatement
    | DoWhileStatement
    | ContinueStatement
    | BreakStatement
    | ReturnStatement
    | ThrowStatement
    | VariableDeclarationStatement
    | IdentifierList
    | IndexAccess
    | MemberAccess
    | ElementaryTypeName
    | NewExpression
    | Expression
    | ExpressionList
    | NameValueList
    | NameValue
    | FunctionCall
    | FunctionCallArguments
    | AssemblyBlock
    | AssemblyItem
    | AssemblyCall
    | AssemblyLocalDefinition
    | AssemblyAssignment
    | AssemblyIdentifierOrList
    | AssemblyIdentifierList
    | AssemblyStackAssignment
    | LabelDefinition
    | AssemblySwitch
    | AssemblyCase
    | AssemblyFunctionDefinition
    | AssemblyFunctionReturns
    | AssemblyFor
    | AssemblyIf
    | AssemblyLiteral
    | SubAssembly
    | TupleExpression
    | ElementaryTypeNameExpression
    | HexLiteral
    | StringLiteral
    | NumberLiteral
    | Identifier
    | UnaryOperation
    | BinaryOperation
    | Conditional;
  export type Expression =
    | IndexAccess
    | TupleExpression
    | BinaryOperation
    | Conditional
    | MemberAccess
    | PrimaryExpression
    | FunctionCall;
  export type PrimaryExpression =
    | BooleanLiteral
    | NumberLiteral
    | Identifier
    | TupleExpression
    | ElementaryTypeNameExpression;
  export type SimpleStatement =
    | VariableDeclaration
    | ExpressionStatement;
  export type TypeName =
    | ElementaryTypeName
    | UserDefinedTypeName
    | Mapping
    | FunctionTypeName;
  export type Statement =
    | IfStatement
    | WhileStatement
    | ForStatement
    | Block
    | InlineAssemblyStatement
    | DoWhileStatement
    | ContinueStatement
    | BreakStatement
    | ReturnStatement
    | ThrowStatement
    | SimpleStatement
    | VariableDeclarationStatement;

  export type VisitorBase = {
    [NodeType in ASTNodeTypeString]: ((node: BaseASTNode) => any) | undefined
  }

  export type ASTNodeByTypeString<Type, T extends ASTNode = ASTNode> = T extends ASTNode ? (T['type'] extends Type ?  T : never) : never

  export type ASTNodeTypeMap = {
    [Type in ASTNodeTypeString]: ASTNodeByTypeString<Type>
  };

  type Visitor_Base = {
    [Type in ASTNodeTypeString]?: (node: ASTNodeByTypeString<Type>) => any;
  }

  export interface Visitor extends Visitor_Base {

    // Start of :exit handler for each type. Must be consistent with Visitor_Base
    'SourceUnit:exit'?: (node: SourceUnit) => any;
    'PragmaDirective:exit'?: (node: PragmaDirective) => any;
    'PragmaName:exit'?: (node: PragmaName) => any;
    'PragmaValue:exit'?: (node: PragmaValue) => any;
    'Version:exit'?: (node: Version) => any;
    'VersionOperator:exit'?: (node: VersionOperator) => any;
    'VersionConstraint:exit'?: (node: VersionConstraint) => any;
    'ImportDeclaration:exit'?: (node: ImportDeclaration) => any;
    'ImportDirective:exit'?: (node: ImportDirective) => any;
    'ContractDefinition:exit'?: (node: ContractDefinition) => any;
    'InheritanceSpecifier:exit'?: (node: InheritanceSpecifier) => any;
    'StateVariableDeclaration:exit'?: (node: StateVariableDeclaration) => any;
    'UsingForDeclaration:exit'?: (node: UsingForDeclaration) => any;
    'StructDefinition:exit'?: (node: StructDefinition) => any;
    'ModifierDefinition:exit'?: (node: ModifierDefinition) => any;
    'ModifierInvocation:exit'?: (node: ModifierInvocation) => any;
    'FunctionDefinition:exit'?: (node: FunctionDefinition) => any;
    'ModifierList:exit'?: (node: ModifierList) => any;
    'EventDefinition:exit'?: (node: EventDefinition) => any;
    'EmitStatement:exit'?: (node: EmitStatement) => any;
    'EnumValue:exit'?: (node: EnumValue) => any;
    'EnumDefinition:exit'?: (node: EnumDefinition) => any;
    'ParameterList:exit'?: (node: ParameterList) => any;
    'Parameter:exit'?: (node: Parameter) => any;
    'EventParameterList:exit'?: (node: EventParameterList) => any;
    'EventParameter:exit'?: (node: EventParameter) => any;
    'FunctionTypeParameterList:exit'?: (node: FunctionTypeParameterList) => any;
    'FunctionTypeParameter:exit'?: (node: FunctionTypeParameter) => any;
    'VariableDeclaration:exit'?: (node: VariableDeclaration) => any;
    'TypeName:exit'?: (node: TypeName) => any;
    'ArrayTypeName:exit'?: (node: ArrayTypeName) => any;
    'UserDefinedTypeName:exit'?: (node: UserDefinedTypeName) => any;
    'Mapping:exit'?: (node: Mapping) => any;
    'FunctionTypeName:exit'?: (node: FunctionTypeName) => any;
    'StorageLocation:exit'?: (node: StorageLocation) => any;
    'StateMutability:exit'?: (node: StateMutability) => any;
    'Block:exit'?: (node: Block) => any;
    'LineComment:exit'?: (node: LineComment) => any;
    'BlockComment:exit'?: (node: BlockComment) => any;
    'ExpressionStatement:exit'?: (node: ExpressionStatement) => any;
    'IfStatement:exit'?: (node: IfStatement) => any;
    'WhileStatement:exit'?: (node: WhileStatement) => any;
    'ForStatement:exit'?: (node: ForStatement) => any;
    'InlineAssemblyStatement:exit'?: (node: InlineAssemblyStatement) => any;
    'DoWhileStatement:exit'?: (node: DoWhileStatement) => any;
    'ContinueStatement:exit'?: (node: ContinueStatement) => any;
    'BreakStatement:exit'?: (node: BreakStatement) => any;
    'ReturnStatement:exit'?: (node: ReturnStatement) => any;
    'ThrowStatement:exit'?: (node: ThrowStatement) => any;
    'VariableDeclarationStatement:exit'?: (node: VariableDeclarationStatement) => any;
    'IdentifierList:exit'?: (node: IdentifierList) => any;
    'ElementaryTypeName:exit'?: (node: ElementaryTypeName) => any;
    'NewExpression:exit'?: (node: NewExpression) => any;
    'Expression:exit'?: (node: Expression) => any;
    'ExpressionList:exit'?: (node: ExpressionList) => any;
    'NameValueList:exit'?: (node: NameValueList) => any;
    'NameValue:exit'?: (node: NameValue) => any;
    'FunctionCall:exit'?: (node: FunctionCall) => any;
    'FunctionCallArguments:exit'?: (node: FunctionCallArguments) => any;
    'AssemblyBlock:exit'?: (node: AssemblyBlock) => any;
    'AssemblyItem:exit'?: (node: AssemblyItem) => any;
    'AssemblyCall:exit'?: (node: AssemblyCall) => any;
    'AssemblyLocalDefinition:exit'?: (node: AssemblyLocalDefinition) => any;
    'AssemblyAssignment:exit'?: (node: AssemblyAssignment) => any;
    'AssemblyIdentifierOrList:exit'?: (node: AssemblyIdentifierOrList) => any;
    'AssemblyIdentifierList:exit'?: (node: AssemblyIdentifierList) => any;
    'AssemblyStackAssignment:exit'?: (node: AssemblyStackAssignment) => any;
    'LabelDefinition:exit'?: (node: LabelDefinition) => any;
    'AssemblySwitch:exit'?: (node: AssemblySwitch) => any;
    'AssemblyCase:exit'?: (node: AssemblyCase) => any;
    'AssemblyFunctionDefinition:exit'?: (node: AssemblyFunctionDefinition) => any;
    'AssemblyFunctionReturns:exit'?: (node: AssemblyFunctionReturns) => any;
    'AssemblyFor:exit'?: (node: AssemblyFor) => any;
    'AssemblyIf:exit'?: (node: AssemblyIf) => any;
    'AssemblyLiteral:exit'?: (node: AssemblyLiteral) => any;
    'SubAssembly:exit'?: (node: SubAssembly) => any;
    'TupleExpression:exit'?: (node: TupleExpression) => any;
    'ElementaryTypeNameExpression:exit'?: (node: ElementaryTypeNameExpression) => any;
    'StringLiteral:exit'?: (node: StringLiteral) => any;
    'NumberLiteral:exit'?: (node: NumberLiteral) => any;
    'Identifier:exit'?: (node: Identifier) => any;
    'IndexAccess:exit'?: (node: IndexAccess) => any;
    'MemberAccess:exit'?: (node: MemberAccess) => any;
    'UnaryOperation:exit'?: (node: UnaryOperation) => any;
    'BinaryOperation:exit'?: (node: BinaryOperation) => any;
    'Conditional:exit'?: (node: Conditional) => any;
  }
  export interface ParserOpts {
    tolerant?: boolean;
    range?: boolean;
    loc?: boolean;
  }
  export function parse(sourceCode: string, parserOpts: ParserOpts): SourceUnit;
  export function visit(ast: ASTNode, visitor: Visitor): void;
}
