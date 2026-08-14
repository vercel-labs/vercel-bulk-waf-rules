import type {
  Diagnostic,
  MigrationProduct,
  PlanOperation,
  SourceSnapshot,
  TranslationBatch,
} from './model.js';

/** Provider API boundary. Discovery is read-only and returns durable evidence. */
export interface ProviderConnector<TSnapshot extends SourceSnapshot = SourceSnapshot> {
  readonly provider: string;
  readonly adapterVersion: string;
  scan(): Promise<TSnapshot>;
}

/** Provider/product semantic boundary. No target behavior belongs here. */
export interface DomainTranslator<TSnapshot extends SourceSnapshot, TDomainModel> {
  readonly product: MigrationProduct;
  translate(snapshot: TSnapshot): Promise<TranslationBatch<TDomainModel>>;
}

export interface CompilationResult {
  readonly operations: readonly PlanOperation[];
  readonly diagnostics: readonly Diagnostic[];
}

/** Target capability boundary. Compilers are pure and never mutate Vercel. */
export interface TargetCompiler<TDomainModel> {
  readonly target: 'vercel';
  readonly product: MigrationProduct;
  compile(resources: readonly TDomainModel[]): CompilationResult;
}
