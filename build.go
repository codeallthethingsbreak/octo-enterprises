import go

class AuthTestConfig extends DataFlow::Configuration {

  AuthTestConfig() { this = "auth-test-config" }

  override predicate isSource(DataFlow::Node source) {
    source = any(DataFlow::CallNode cn |
      cn.getTarget().hasQualifiedName("github.com/minio/minio/cmd", "isReqAuthenticated")
    ).getResult()
  }

  override predicate isSink(DataFlow::Node sink) {
    sink = any(DataFlow::EqualityTestNode n).getAnOperand()
  }

}

EqualityTestExpr getAnAuthCheck() {
  exists(AuthTestConfig config, DataFlow::Node sink, DataFlow::EqualityTestNode comparison |
    config.hasFlow(_, sink) and comparison.getAnOperand() = sink |
    result = comparison.asExpr()
  )
}

from IfStmt i
where
i.getCond() = getAnAuthCheck() and
i.getCond().(EqualityTestExpr).getAnOperand().(Ident).getName() = "ErrNone"
and not i.getThen().getAStmt() instanceof ReturnStmt
select i
