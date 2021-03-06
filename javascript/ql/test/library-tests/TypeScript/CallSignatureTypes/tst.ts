interface Callable {
  (x: number): string;
}

interface OverloadedCallable {
  (x: number): number;
  (x: string): string;
  (x: any): any;
}

interface Newable {
  new (x: number): any; 
}

interface OverloadedNewable {
  new (x: number): OverloadedNewable;
  new (x: any): any; 
}

interface Method {
  method(x: number): string;
  
  overloadedMethod(x: number): number;
  overloadedMethod(x: string): string;
  overloadedMethod(x: any): any;
}

let m: Method;
m.method(42);
m.overloadedMethod("foo");

interface FunctionTypeField {
  callback: (x: number) => string;
}

interface Generic<T> {
  method(x: T): T;
}

function foo(g: Generic<string>) {
  return g.method("foo");
}
