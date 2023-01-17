const {
  npm_package_name: pkgName = '',
  npm_package_version: pkgVersion = '',
  NODE_ENV = ''
} = process.env

const SERVICE = `${pkgName}@${pkgVersion}`
const IS_PRODUCTION = NODE_ENV === 'production'

export { SERVICE, IS_PRODUCTION }
