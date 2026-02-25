import asyncio
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import AsyncMessage
import email
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PhishingHandler(AsyncMessage):
    async def handle_message(self, message):
        logger.info("=== NEW EMAIL RECEIVED ===")
        logger.info(f"From: {message['from']}")
        logger.info(f"To: {message['to']}")
        logger.info(f"Subject: {message['subject']}")
        logger.info("=== END ===")

if __name__ == "__main__":
    handler = PhishingHandler()
    controller = Controller(handler, hostname="0.0.0.0", port=1025)
    controller.start()
    logger.info("SMTP server running on port 1025")
    asyncio.get_event_loop().run_forever()