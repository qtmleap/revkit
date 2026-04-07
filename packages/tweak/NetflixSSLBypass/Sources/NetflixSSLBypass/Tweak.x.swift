import Orion
import NetflixSSLBypassC
import UIKit
import OSLog

private let logger = Logger(subsystem: "dev.tkgstrator.charon", category: "tweak")

class ViewControllerHook: ClassHook<UIViewController> {
    func viewDidAppear(_ animated: Bool) {
        let className = String(describing: type(of: target))
        logger.info("[NFXBypass] viewDidAppear: \(className, privacy: .public)")
        orig.viewDidAppear(animated)
    }
}
