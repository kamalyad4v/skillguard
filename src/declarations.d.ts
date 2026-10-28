declare module "react" {
  export const useEffect: any;
  export const useLayoutEffect: any;
  export const useRef: any;
  export const useState: any;
  const React: any;
  export default React;
}

declare module "react/jsx-runtime" {
  export const jsx: any;
  export const jsxs: any;
  export const Fragment: any;
}

declare namespace JSX {
  interface IntrinsicElements {
    [elemName: string]: any;
  }
}
