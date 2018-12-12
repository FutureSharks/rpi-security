# -*- coding: utf-8 -*-

import logging
from telegram.ext import Updater, CommandHandler, RegexHandler
import _thread


logging.getLogger("telegram").setLevel(logging.ERROR)


logger = logging.getLogger()


def telegram_bot(rpis, camera):
    """
    This function runs the telegram bot that responds to commands like /enable, /disable or /status.
    """
    def save_chat_id(bot, update):
        if 'telegram_chat_ids' not in rpis.saved_data or rpis.saved_data['telegram_chat_ids'] is None:
            rpis.save_telegram_chat_id(update.message.chat_id)
            logger.debug('Set Telegram chat_id {0}'.format(update.message.chat_id))
        else:
            if len(rpis.saved_data['telegram_chat_ids']) < rpis.telegram_users_number:
                if update.message.chat_id not in rpis.saved_data['telegram_chat_ids']:
                    rpis.save_telegram_chat_id(update.message.chat_id)
                    logger.debug('Set Telegram chat_id {0}'.format(update.message.chat_id))

    def debug(bot, update):
        logger.debug('Received Telegram bot message: {0}'.format(update.message.text))

    def check_chat_id(update):
        if 'telegram_chat_ids' in rpis.saved_data and update.message.chat_id not in rpis.saved_data['telegram_chat_ids']:
            logger.debug('Ignoring Telegam update with filtered chat id {0}: {1}'.format(update.message.chat_id, update.message.text))
            return False
        else:
            return True

    def help(bot, update):
        if check_chat_id(update):
            bot.sendMessage(update.message.chat_id, parse_mode='Markdown', text='/status: Request status\n/disable: Disable alarm\n/enable: Enable alarm\n/photo: Take a photo\n/gif: Take a gif\n', timeout=10)

    def status(bot, update):
        if check_chat_id(update):
            bot.sendMessage(update.message.chat_id, parse_mode='Markdown', text=rpis.state.generate_status_text(), timeout=10)

    def disable(bot, update):
        if check_chat_id(update):
            rpis.state.update_state('disabled')

    def enable(bot, update):
        if check_chat_id(update):
            rpis.state.update_state('disarmed')

    def photo(bot, update):
        if check_chat_id(update):
            photo = camera.take_photo()
            rpis.telegram_send_file(photo)

    def gif(bot, update):
        if check_chat_id(update):
            gif = camera.take_gif()
            rpis.telegram_send_file(gif)

    def error_callback(bot, update, error):
        logger.error('Update "{0}" caused error "{1}"'.format(update, error))

    try:
        updater = Updater(rpis.telegram_bot_token)
        dp = updater.dispatcher
        dp.add_handler(RegexHandler('.*', save_chat_id), group=1)
        dp.add_handler(RegexHandler('.*', debug), group=2)
        dp.add_handler(CommandHandler("help", help), group=3)
        dp.add_handler(CommandHandler("status", status), group=3)
        dp.add_handler(CommandHandler("disable", disable), group=3)
        dp.add_handler(CommandHandler("enable", enable), group=3)
        dp.add_handler(CommandHandler("photo", photo), group=3)
        dp.add_handler(CommandHandler("gif", gif), group=3)
        dp.add_error_handler(error_callback)
        updater.start_polling(timeout=10)
    except Exception as e:
        logger.error('Telegram Updater failed to start with error {0}'.format(repr(e)))
        _thread.interrupt_main()
    else:
        logger.info("thread running")
